const container = document.getElementById('canvas-globe-container');
const renderer = new THREE.WebGLRenderer({ alpha: true });
renderer.setSize(window.innerWidth, window.innerHeight);
container.appendChild(renderer.domElement);

renderer.setClearColor(0x000000); 

const scene = new THREE.Scene();

const config = {
    globe: {
        radius: 300,
        rotationSpeed: 0.001,
        textureUrl: 'https://i.ibb.co/gZRRfzN/globe-map.png',
        width: window.innerWidth,
        height: window.innerHeight,
    },
    camera: {
        fov: 75, 
        aspect: window.innerWidth / window.innerHeight,
        near: 0.1, 
        far: 1000, 
        position: {
            x: 0,
            y: 0,
            z: 600, 
        },
    },
};

const camera = new THREE.PerspectiveCamera(
    config.camera.fov,
    config.camera.aspect,
    config.camera.near,
    config.camera.far
);

camera.position.set(config.camera.position.x, config.camera.position.y, config.camera.position.z);

const geometry = new THREE.SphereGeometry(config.globe.radius, 32, 16);
const material = new THREE.MeshBasicMaterial({
    color: 0x0000FF, 
    transparent: true,
    opacity: 6,
});
const globe = new THREE.Mesh(geometry, material);
scene.add(globe);

const textureLoader = new THREE.TextureLoader();
let texture = null;

textureLoader.load(
    config.globe.textureUrl,
    tex => {
        texture = tex;

        const maxAnisotropy = renderer.capabilities.getMaxAnisotropy();
        texture.anisotropy = maxAnisotropy;

        texture.generateMipmaps = true;
        texture.minFilter = THREE.LinearFilter;
        texture.magFilter = THREE.LinearFilter;

        globe.material.map = texture;
        globe.material.needsUpdate = true;
    },
    undefined,
    error => {
        console.error('An error has occurred:', error);
    }
);

function onWindowResize() {
    const width = window.innerWidth;
    const height = window.innerHeight;

    renderer.setSize(width, height);

    camera.aspect = width / height;
    camera.updateProjectionMatrix();

    config.globe.width = width;
    config.globe.height = height;
}
window.addEventListener('resize', onWindowResize);

function animate() {
    requestAnimationFrame(animate);
    if (texture) {
        globe.rotation.y += config.globe.rotationSpeed; 
    }
    renderer.render(scene, camera);
}

animate();


function latLngToXYZ(lat, lng, radius) {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (180 - lng) * (Math.PI / 180);

    const x = radius * Math.sin(phi) * Math.cos(theta);
    const y = radius * Math.cos(phi);
    const z = radius * Math.sin(phi) * Math.sin(theta);

    return { x, y, z };
}

function addMarker(lat, lng, label) {
    const markerRadius = 10; 
    const markerGeometry = new THREE.SphereGeometry(markerRadius, 16, 16);
    const markerMaterial = new THREE.MeshBasicMaterial({ color: 0xff0000 }); 
    const marker = new THREE.Mesh(markerGeometry, markerMaterial);

    const position = latLngToXYZ(lat, lng, config.globe.radius + markerRadius);
    marker.position.set(position.x, position.y, position.z);
    marker.userData.label = label;
    globe.add(marker);
}

function addCurrentLocationMarker() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
            (position) => {
                const { latitude, longitude } = position.coords;
                console.log(`Current Location: Latitude ${latitude}, Longitude ${longitude}`);
                addMarker(20, -110, `Latitude: ${750}, Longitude: ${750}`);
            },
            (error) => {
                console.error('Error fetching location:', error.message);
            },
            { enableHighAccuracy: true }
        );
    } else {
        console.error('Geolocation is not supported by this browser.');
    }
}

addCurrentLocationMarker();



const raycaster = new THREE.Raycaster();
const mouse = new THREE.Vector2();
let selectedMarker = null;


function onMouseMove(event) {
    mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
    mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(globe.children);

    if (intersects.length > 0) {
        if (selectedMarker !== intersects[0].object) {
            selectedMarker = intersects[0].object;
            showPopup(event, selectedMarker.userData.label);
        }
    } else {
        selectedMarker = null;
        hidePopup();
    }
}

// Popup handling
const popup = document.createElement('div');
popup.id = 'popup';
popup.style.position = 'absolute';
popup.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
popup.style.color = 'white';
popup.style.padding = '5px 10px';
popup.style.borderRadius = '5px';
popup.style.pointerEvents = 'none';
popup.style.display = 'none';
document.body.appendChild(popup);

function showPopup(event, text) {
    popup.innerHTML = `Location: ${text}`;
    popup.style.left = `${event.clientX + 10}px`;
    popup.style.top = `${event.clientY + 10}px`;
    popup.style.display = 'block';
}

function hidePopup() {
    popup.style.display = 'none';
}


renderer.domElement.addEventListener('mousemove', onMouseMove);