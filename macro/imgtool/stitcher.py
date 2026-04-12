# test806 : stitcher
import os
from collections import deque
import cv2
import numpy as np

class Stitcher:
    def __init__(self):
        self.patchsize = 64
        self.patchnum = 400
        self.exts = ['.webp', '.png', '.jpg', '.jpeg']
        self.result = "result.png"

    # find the offset between two images
    def find_offset(self, img1, img2):
        # convert to grayscale for easier processing
        gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)
        h1, w1 = gray1.shape
        h2, w2 = gray2.shape

        # determine patch size
        patch_size = min(self.patchsize, h1 // 2, w1 // 2)
        if patch_size < 16: return None # image too small to process
        stride = max(8, patch_size // 2)

        # find valid patches from img1
        valid_patches = [ ]
        for y in range(0, h1 - patch_size + 1, stride):
            for x in range(0, w1 - patch_size + 1, stride):
                patch = gray1[y:y+patch_size, x:x+patch_size]
                if np.std(patch) > 5: # pass background patches
                    valid_patches.append((x, y, patch))

        # select border samples
        if len(valid_patches) > self.patchnum:
            def distance_to_edge(p):
                px, py, _ = p
                return min(py, h1 - py, px, w1 - px)
            valid_patches.sort(key=distance_to_edge)
            valid_patches = valid_patches[:self.patchnum]

        # voting for offsets that patch matches
        vote_dict = { }
        for px, py, patch in valid_patches:
            res = cv2.matchTemplate(gray2, patch, cv2.TM_CCOEFF_NORMED)
            loc = np.where(res >= 0.6) # threshold for "similar enough"
            
            for pt_y, pt_x in zip(*loc):
                dx, dy = px - pt_x, py - pt_y
                key = ((dx // 3) * 3, (dy // 3) * 3) # cut off to 3 pixels
                if key not in vote_dict:
                    vote_dict[key] = [ ]
                vote_dict[key].append((dx, dy))

        if not vote_dict:
            return None # no match

        # sort votes by number of votes
        sorted_votes = sorted(vote_dict.items(), key=lambda x: len(x[1]), reverse=True)
        for (bin_dx, bin_dy), exact_votes in sorted_votes[:5]:
            if len(exact_votes) < 3:
                continue # need at least 3 votes to be reliable

            # median for votes
            dx = int(round(np.median([v[0] for v in exact_votes])))
            dy = int(round(np.median([v[1] for v in exact_votes])))
            
            # get overlapping region coordinates in both images
            x_start_1, y_start_1 = max(0, dx), max(0, dy)
            x_end_1, y_end_1 = min(w1, dx + w2), min(h1, dy + h2)
            x_start_2, y_start_2 = max(0, -dx), max(0, -dy)
            x_end_2, y_end_2 = min(w2, w1 - dx), min(h2, h1 - dy)
            w_ov = x_end_1 - x_start_1
            h_ov = y_end_1 - y_start_1
            
            # check if overlap is large enough and has enough texture to be reliable
            if w_ov >= patch_size and h_ov >= patch_size:
                ov1 = gray1[y_start_1:y_end_1, x_start_1:x_end_1]
                ov2 = gray2[y_start_2:y_end_2, x_start_2:x_end_2]
                if np.std(ov1) < 5 or np.std(ov2) < 5:
                    continue
                    
                sim = cv2.matchTemplate(ov1, ov2, cv2.TM_CCOEFF_NORMED)[0][0]
                if sim > 0.5: # threshold for "good enough" match
                    return dx, dy

        return None
    
    # build a graph of image connections based on offsets
    def build_graph(self, image_paths):
        graph = {path: [] for path in image_paths}
        images = {path: cv2.imread(path) for path in image_paths}

        # find offsets between all image pairs
        for i in range(len(image_paths)):
            for j in range(i + 1, len(image_paths)):
                path1, path2 = image_paths[i], image_paths[j]
                img1, img2 = images[path1], images[path2]
                
                # find offset and add to graph
                offset = self.find_offset(img1, img2)
                if offset:
                    dx, dy = offset
                    graph[path1].append((path2, dx, dy))
                    graph[path2].append((path1, -dx, -dy))
                    print(f"matched {os.path.basename(path1)} with {os.path.basename(path2)} (dx:{dx}, dy:{dy})")
                    
        return graph, images
    
    # get global coordinates for each image
    def calculate_global_coords(self, graph):
        visited = set()
        components = [ ]
        
        for node in graph:
            if node not in visited:
                comp_coords = {node: (0, 0)} # start with this image at (0, 0)
                queue = deque([node])
                visited.add(node)
                
                while queue: # BFS
                    current = queue.popleft()
                    cx, cy = comp_coords[current] # current image's global coordinates
                    
                    for neighbor, dx, dy in graph[current]:
                        if neighbor not in comp_coords: # if we haven't assigned coordinates to this neighbor yet
                            comp_coords[neighbor] = (cx + dx, cy + dy)
                            visited.add(neighbor)
                            queue.append(neighbor)
                            
                components.append(comp_coords) # add component to list
                
        if not components:
            return { }
        return max(components, key=len) # return largest component's coordinates
    
    # stitch all images together
    def stitch_folder(self, folder_path):
        # get image paths
        image_paths = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if os.path.splitext(f)[1].lower() in self.exts]
        if not image_paths:
            raise ValueError("No valid images found in the folder.")

        # build graph and calculate global coordinates
        print(f"stitching {len(image_paths)} images...")
        graph, images = self.build_graph(image_paths)
        global_coords = self.calculate_global_coords(graph)
        if not global_coords:
            raise ValueError("No connections found between images.")

        # get canvas size by finding bounding box
        min_x, min_y = float('inf'), float('inf')
        max_x, max_y = float('-inf'), float('-inf')
        for path, (gx, gy) in global_coords.items():
            h, w = images[path].shape[:2]
            min_x, min_y = min(min_x, gx), min(min_y, gy)
            max_x, max_y = max(max_x, gx + w), max(max_y, gy + h)
        canvas_w, canvas_h = int(max_x - min_x), int(max_y - min_y)

        # make canvas and get offsets
        canvas = np.zeros((canvas_h, canvas_w, 3), dtype=np.uint8)
        offset_x, offset_y = int(-min_x), int(-min_y)
        
        # add images to canvas
        for path, (gx, gy) in global_coords.items():
            img = images[path]
            h, w = img.shape[:2]
            x, y = int(gx + offset_x), int(gy + offset_y)
            canvas[y : y + h, x : x + w] = img
            
        cv2.imwrite(self.result, canvas)
        print(f"{len(global_coords)} images stitched into {self.result}")

# s = Stitcher()
# s.stitch_folder("a/")
