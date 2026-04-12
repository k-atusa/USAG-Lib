# testXXX : mapgen
import csv
import json
import os

### ========== Controls ========== ###
# WASD + Shift + Ctrl
# Mouse Drag

### ========== Example datas ========== ###
# node.csv
"""
ID,X,Y,Z,NAME,STYLE
A1,0,0,0,Sun,Star
A2,100,0,0,Earth,Planet
A3,100,10,0,Moon,Moon
A4,400,-100,500,Jupiter,Planet
C1,0,64,0,,
C2,0,-64,0,,
"""

# edge.csv
"""
START,END,NAME,STYLE
A2,A1,Route 1,Rocket
A2,A4,Route 2,Rocket
A2,A3,,
"""

# style.csv
"""
NAME,COLOR,R
Star,yellow,5
Planet,green,2
Moon,white,1
Rocket,red,1
"""

### ========== HTML output template ========== ###
# replace placeholders: __LANGUAGE__, __TITLE__, __NODES__, __EDGES__, __STYLES__
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="__LANGUAGE__">
<head>
    <meta charset="UTF-8">
    <title>__TITLE__</title>
    <style>
        body { margin: 0; overflow: hidden; font-family: sans-serif; background-color: #020205; }
        canvas { display: block; }
        #ui-layer { position: absolute; top: 10px; left: 10px; color: white; background: rgba(0,0,0,0.85); padding: 15px; border-radius: 8px; z-index: 10; border: 1px solid #444; width: 200px; }
        #hud-layer { position: absolute; top: 10px; right: 10px; color: #00ff00; background: rgba(0,0,0,0.85); padding: 15px; border-radius: 8px; text-align: right; z-index: 10; font-family: monospace; border: 1px solid #444; pointer-events: none; line-height: 1.5; }
        .label { color: white; background: rgba(0,0,0,0.6); padding: 4px 6px; border-radius: 4px; font-size: 11px; pointer-events: none; border: 1px solid #555; white-space: nowrap; text-align: center; }
        .edge-label { background: rgba(50,0,100,0.7); border-color: #aa00ff; color: #ddaaff; font-size: 10px; }
        .control-group { margin-bottom: 12px; }
        label { cursor: pointer; font-size: 13px; display: block; margin-bottom: 5px; }
        input[type="range"] { width: 100%; cursor: pointer; }
        .hud-highlight { color: #ffaa00; margin-top: 5px; padding-top: 5px; border-top: 1px solid #444; }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/renderers/CSS2DRenderer.js"></script>
</head>
<body>
    <div id="ui-layer">
        <div class="control-group">
            <label>Speed Control</label>
            <input type="range" id="opt-speed" min="-3" max="6" step="0.1" value="0">
        </div>
        <div class="control-group"><label><input type="checkbox" id="opt-names" checked> View Name</label></div>
        <div class="control-group"><label><input type="checkbox" id="opt-coords"> View Coordinates</label></div>
        <div class="control-group"><label><input type="checkbox" id="opt-axes" checked> Enable Axes</label></div>
        <div class="control-group"><label><input type="checkbox" id="opt-grid" checked> Enable Grid</label></div>
    </div>
    <div id="hud-layer">
        <div id="hud-pos"></div>
        <div id="hud-dir"></div>
        <div id="hud-spd" class="hud-highlight"></div>
    </div>

    <script>
        const rawNodes = __NODES__;
        const rawEdges = __EDGES__;
        const rawStyles = __STYLES__;

        const styleMap = {};
        rawStyles.forEach(s => styleMap[s.NAME] = { color: s.COLOR, r: parseFloat(s.R) });

        const getS = (name, isN) => {
            const s = styleMap[name] || {};
            return { color: s.color || (isN ? '#aaa' : '#666'), r: isNaN(s.r) ? (isN ? 1 : 0.5) : s.r };
        };

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.001, 10000000);
        const renderer = new THREE.WebGLRenderer({antialias:true});
        renderer.setSize(window.innerWidth, window.innerHeight);
        document.body.appendChild(renderer.domElement);

        const labelRenderer = new THREE.CSS2DRenderer();
        labelRenderer.setSize(window.innerWidth, window.innerHeight);
        labelRenderer.domElement.style.position = 'absolute';
        labelRenderer.domElement.style.top = '0';
        labelRenderer.domElement.style.pointerEvents = 'none';
        document.body.appendChild(labelRenderer.domElement);

        scene.add(new THREE.AmbientLight(0xffffff, 0.8));
        const nodeObjs = {}, allLabels = [];
        let minX=Infinity, maxX=-Infinity, minZ=Infinity, maxZ=-Infinity, sumX=0, sumY=0, sumZ=0, cnt=0;

        // 1. Node Rendering
        rawNodes.forEach(n => {
            const x=parseFloat(n.X)||0, y=parseFloat(n.Y)||0, z=parseFloat(n.Z)||0, s=getS(n.STYLE, true);
            if(s.r <= 0) return;
            
            const m = new THREE.Mesh(new THREE.SphereGeometry(s.r, 16, 16), new THREE.MeshLambertMaterial({color:s.color}));
            m.position.set(x,y,z); 
            scene.add(m); 
            
            const hasName = n.NAME && n.NAME.trim() !== '';
            const nodeName = hasName ? n.NAME.trim() : '';
            nodeObjs[n.ID] = { mesh: m, name: nodeName }; // store object reference
            
            sumX+=x; sumY+=y; sumZ+=z; cnt++;
            if(x<minX) minX=x; if(x>maxX) maxX=x; if(z<minZ) minZ=z; if(z>maxZ) maxZ=z;

            const div = document.createElement('div'); div.className = 'label';
            div.dataset.hasName = hasName;
            div.innerHTML = `<div class="n-txt">${nodeName}</div><div class="c-txt">(${x}, ${y}, ${z})</div>`;
            const l = new THREE.CSS2DObject(div); l.position.set(0, s.r + (s.r * 0.2) + 0.1, 0); m.add(l);
            allLabels.push(div);
        });

        // 2. Edge Rendering
        rawEdges.forEach(e => {
            const sObj = nodeObjs[e.START];
            const eObj = nodeObjs[e.END];
            if(!sObj || !eObj) return;

            const sN = sObj.mesh;
            const eN = eObj.mesh;
            const s = getS(e.STYLE, false);

            if(s.r > 0) {
                const g = new THREE.BufferGeometry().setFromPoints([sN.position, eN.position]);
                scene.add(new THREE.Line(g, new THREE.LineBasicMaterial({color:s.color})));
                
                const mid = new THREE.Vector3().lerpVectors(sN.position, eN.position, 0.5);
                const hasName = e.NAME && e.NAME.trim() !== '';
                const edgeName = hasName ? e.NAME : '';
                const linkText = `${sObj.name} ↔ ${eObj.name}`;
                
                const div = document.createElement('div'); div.className = 'label edge-label';
                div.dataset.hasName = hasName;
                div.innerHTML = `<div class="n-txt">${edgeName}</div><div class="c-txt">${linkText}</div>`;
                const l = new THREE.CSS2DObject(div); l.position.copy(mid); scene.add(l);
                allLabels.push(div);
            }
        });

        // 3. Sync Grid and Axes
        if(cnt>0) {
            const avg = new THREE.Vector3(sumX/cnt, sumY/cnt, sumZ/cnt);
            camera.position.set(avg.x+20, avg.y+10, avg.z+20); camera.lookAt(avg);
            
            // get farthest distance from (0, 0, 0)
            const maxDist = Math.max(Math.abs(minX), Math.abs(maxX), Math.abs(minZ), Math.abs(maxZ), 100);
            const size = maxDist * 2.5; 
            
            const g = new THREE.GridHelper(size, 40, 0x444444, 0x111111); 
            g.position.set(0, 0, 0);
            scene.add(g); window.grid=g;
            
            const ax = new THREE.AxesHelper(size/2); 
            ax.position.set(0, 0, 0);
            scene.add(ax); window.axes=ax;
        }

        let speedExp = 0; 
        let moveSpeed = 1.0;
        const speedSlider = document.getElementById('opt-speed');
        const hudSpd = document.getElementById('hud-spd');

        // Speed View Update
        const updateSpeedHUD = () => {
            let displaySpeed = moveSpeed >= 100 ? moveSpeed.toLocaleString('ko-KR', {maximumFractionDigits: 0}) : moveSpeed.toFixed(3);
            hudSpd.innerText = `SPD: ${displaySpeed}`;
        };

        speedSlider.oninput = (e) => {
            speedExp = parseFloat(e.target.value);
            moveSpeed = Math.pow(10, speedExp);
            updateSpeedHUD();
        };
        updateSpeedHUD(); // init view

        let pitch = camera.rotation.x, yaw = camera.rotation.y, isDown = false;
        document.addEventListener('mousedown', (e) => { if(e.target.tagName !== 'INPUT') isDown=true; });
        document.addEventListener('mouseup', () => isDown=false);
        document.addEventListener('mousemove', (e) => {
            if(isDown) {
                yaw -= e.movementX * 0.003;
                pitch -= e.movementY * 0.003;
                pitch = Math.max(-Math.PI/2, Math.min(Math.PI/2, pitch));
                camera.quaternion.setFromEuler(new THREE.Euler(pitch, yaw, 0, 'YXZ'));
            }
        });

        const keys = {};
        document.addEventListener('keydown', (e) => keys[e.key.toLowerCase()] = true);
        document.addEventListener('keyup', (e) => keys[e.key.toLowerCase()] = false);

        const optN = document.getElementById('opt-names'), optC = document.getElementById('opt-coords');
        const sync = () => {
            allLabels.forEach(l => {
                const showN = optN.checked && l.dataset.hasName === 'true';
                const showC = optC.checked;
                l.style.display = (showN || showC) ? 'block' : 'none';
                l.querySelector('.n-txt').style.display = showN ? 'block' : 'none';
                l.querySelector('.c-txt').style.display = showC ? 'block' : 'none';
            });
        };
        optN.onchange = sync; optC.onchange = sync;
        document.getElementById('opt-axes').onchange = (e) => window.axes.visible = e.target.checked;
        document.getElementById('opt-grid').onchange = (e) => window.grid.visible = e.target.checked;
        sync();

        function animate() {
            requestAnimationFrame(animate);
            const fwd = new THREE.Vector3(0,0,-1).applyAxisAngle(new THREE.Vector3(0,1,0), yaw);
            const rgt = new THREE.Vector3(1,0,0).applyAxisAngle(new THREE.Vector3(0,1,0), yaw);
            if(keys['w']) camera.position.addScaledVector(fwd, moveSpeed);
            if(keys['s']) camera.position.addScaledVector(fwd, -moveSpeed);
            if(keys['a']) camera.position.addScaledVector(rgt, -moveSpeed);
            if(keys['d']) camera.position.addScaledVector(rgt, moveSpeed);
            if(keys['shift']) camera.position.y += moveSpeed;
            if(keys['control']) camera.position.y -= moveSpeed;
            
            document.getElementById('hud-pos').innerText = `POS: ${camera.position.x.toFixed(1)}, ${camera.position.y.toFixed(1)}, ${camera.position.z.toFixed(1)}`;
            document.getElementById('hud-dir').innerText = `ANG: vertical ${(pitch * 180 / Math.PI).toFixed(1)}°, horizontal ${(((yaw * 180 / Math.PI) % 360 + 360) % 360).toFixed(1)}°`;
            
            renderer.render(scene, camera); labelRenderer.render(scene, camera);
        }
        animate();
        window.onresize = () => {
            camera.aspect=window.innerWidth/window.innerHeight; camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight); labelRenderer.setSize(window.innerWidth, window.innerHeight);
        };
    </script>
</body>
</html>
"""

# load CSV data
def load_csv(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, mode='r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        return [row for row in reader]

# validate data
def validate_data(nodes, edges, styles):
    node_ids = {n.get('ID') for n in nodes if n.get('ID')}
    style_names = {s.get('NAME', '').strip() for s in styles if s.get('NAME')}

    # check if node id, X, Y, Z is not empty
    for i, item in enumerate(nodes):
        if item.get('ID', '').strip() == "":
            raise ValueError(f"node ID is empty at line {i+2}")
        if item.get('X', '').strip() == "":
            raise ValueError(f"node X Position is empty at line {i+2}")
        if item.get('Y', '').strip() == "":
            raise ValueError(f"node Y Position is empty at line {i+2}")
        if item.get('Z', '').strip() == "":
            raise ValueError(f"node Z Position is empty at line {i+2}")
        
    # check if node exists
    for i, item in enumerate(edges):
        src = item.get('START', '').strip()
        dst = item.get('END', '').strip()
        if src not in node_ids or dst not in node_ids:
            raise ValueError(f"node ID '{src}' or '{dst}' is used but not exists at line {i+2}")

    # check if style exists
    for item in nodes + edges:
        style_val = item.get('STYLE', '').strip()
        if style_val != "" and style_val not in style_names:
            raise ValueError(f"style name '{style_val}' is used but not exists")

# generate HTML file
def generate_html(nodes, edges, styles, lang, title, filename):
    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)
    styles_json = json.dumps(styles)

    html_content = HTML_TEMPLATE.replace('__LANGUAGE__', lang)
    html_content = html_content.replace('__TITLE__', title)
    html_content = html_content.replace('__NODES__', nodes_json)
    html_content = html_content.replace('__EDGES__', edges_json)
    html_content = html_content.replace('__STYLES__', styles_json)

    with open(filename, 'w', encoding='utf-8') as f: 
        f.write(html_content)

# Map Generator
def Generate(node_path, edge_path, style_path, lang="ko", title="ExplorerMap", filename="Map3D.html"):
    n = load_csv(node_path)
    e = load_csv(edge_path)
    s = load_csv(style_path)
    validate_data(n, e, s)
    generate_html(n, e, s, lang, title, filename)
    print(f"HTML file generated: {filename}")

# Generate("node.csv", "edge.csv", "style.csv")
