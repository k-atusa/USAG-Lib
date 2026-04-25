# test806 : stitcher
import os
from collections import deque
import cv2
import numpy as np
from concurrent.futures import ThreadPoolExecutor

class Stitcher:
    def __init__(self):
        self.exts = ['.webp', '.png', '.jpg', '.jpeg']
        self.result = "result.png"

        self.edgeLimit = 100 # edge detection threshold
        self.noScrollBar = True # whether to remove scroll bar
        self.patchSize = 100 # patch size for edge detection
        self.stride = 50 # stride for edge detection
        self.patchLimit = 200 # limit for the number of patches
        self.matchLimit = 0.85 # threshold for matching

    def find_offset(self, img1, img2):
        # grayscale images for 'candidate voting'
        gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)
        h1, w1 = gray1.shape
        h2, w2 = gray2.shape

        # extract patched having enough edge (no background)
        candidates = [ ]
        for y in range(0, h1 - self.patchSize + 1, self.stride):
            for x in range(0, int(w1 * (0.95 if self.noScrollBar else 1.0)) - self.patchSize + 1, self.stride):
                patch_gray = gray1[y:y+self.patchSize, x:x+self.patchSize]
                if cv2.Canny(patch_gray, 50, 150).sum() > self.edgeLimit: 
                    candidates.append((x, y, patch_gray))

        # if there are too many candidates, limit them
        if not candidates:
            return None
        if len(candidates) > self.patchLimit:
            np.random.seed(42)
            np.random.shuffle(candidates)
            candidates = candidates[:self.patchLimit]

        vote_dict = { }
        for px, py, patch_gray in candidates:
            # grayscale template matching to find candidate offsets
            res = cv2.matchTemplate(gray2, patch_gray, cv2.TM_CCOEFF_NORMED)
            loc = np.where(res >= self.matchLimit) 
            
            # voting for offsets, 4 pixel unit
            for pt_y, pt_x in zip(*loc):
                dx, dy = px - pt_x, py - pt_y
                key = (round(dx / 4) * 4, round(dy / 4) * 4)
                if key not in vote_dict:
                    vote_dict[key] = [ ]
                vote_dict[key].append((dx, dy))

        # sort votes by count
        if not vote_dict: return None
        sorted_votes = sorted(vote_dict.items(), key=lambda x: len(x[1]), reverse=True)

        # color original pixel validation for top candidates
        for (bin_dx, bin_dy), exact_votes in sorted_votes[:10]:
            if len(exact_votes) < 2: continue # least 2 votes required
            base_dx = int(round(np.median([v[0] for v in exact_votes])))
            base_dy = int(round(np.median([v[1] for v in exact_votes])))
            best_mse = float('inf')
            best_dx, best_dy = base_dx, base_dy

            # +/- 2 pixel local search
            for s_dy in [-2, -1, 0, 1, 2]:
                for s_dx in [-2, -1, 0, 1, 2]:
                    dx = base_dx + s_dx
                    dy = base_dy + s_dy

                    x_start_1, y_start_1 = max(0, dx), max(0, dy)
                    x_end_1, y_end_1 = min(w1, dx + w2), min(h1, dy + h2)
                    x_start_2, y_start_2 = max(0, -dx), max(0, -dy)
                    x_end_2, y_end_2 = min(w2, w1 - dx), min(h2, h1 - dy)

                    w_ov = x_end_1 - x_start_1
                    h_ov = y_end_1 - y_start_1

                    if w_ov < self.patchSize or h_ov < self.patchSize: continue
                    safe_w = int(w_ov * 0.95) if self.noScrollBar else w_ov
                    ov1_color = img1[y_start_1:y_end_1, x_start_1:x_start_1+safe_w]
                    ov2_color = img2[y_start_2:y_end_2, x_start_2:x_start_2+safe_w]

                    # color MSE calculation, lower MSE means better match
                    diff = cv2.absdiff(ov1_color, ov2_color)
                    mse = np.mean(np.square(diff, dtype=np.float32))
                    if mse < best_mse:
                        best_mse = mse
                        best_dx, best_dy = dx, dy

            # final decision, color MSE should be low (50~100)
            if best_mse < 80: 
                return best_dx, best_dy
        return None
    
    # build a graph of image connections based on offsets
    def build_graph(self, image_paths):
        graph = {path: [] for path in image_paths}
        images = {path: cv2.imread(path) for path in image_paths}
        pairs = [(i, j) for i in range(len(image_paths)) for j in range(i + 1, len(image_paths))]

        # pair offset checker
        def check_pair(p):
            i, j = p
            path1, path2 = image_paths[i], image_paths[j]
            offset = self.find_offset(images[path1], images[path2])
            return path1, path2, offset
        with ThreadPoolExecutor() as executor:
            results = executor.map(check_pair, pairs)

        # build graph
        for path1, path2, offset in results:
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

s = Stitcher()
for n in ["a", "b", "c"]:
    s.result = n + ".png"
    s.stitch_folder(n)
