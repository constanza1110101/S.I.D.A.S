// Módulo de visualización 3D con Three.js

import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/examples/jsm/loaders/DRACOLoader.js';
import { Sky } from 'three/examples/jsm/objects/Sky.js';
import { Water } from 'three/examples/jsm/objects/Water.js';

class Battlefield3DVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(75, this.container.clientWidth / this.container.clientHeight, 0.1, 10000);
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.clock = new THREE.Clock();
    
    this.assets = {
      drones: {},
      satellites: {},
      terrain: null,
      ships: {},
      missiles: {}
    };
    
    this.tracks = {};
    this.selectedTrack = null;
    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2();
    
    // Scale for converting coordinates
    this.worldScale = 0.1;  // Scale factor for world coordinates
    
    // Event callbacks
    this.onTrackSelected = null;
    
    this.initialize();
  }
  
  initialize() {
    // Configurar escena
    this.scene.background = new THREE.Color(0x000022);
    this.scene.fog = new THREE.FogExp2(0x000022, 0.0005);
    
    // Configurar renderer
    this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
    this.renderer.setPixelRatio(window.devicePixelRatio);
    this.renderer.shadowMap.enabled = true;
    this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    this.container.appendChild(this.renderer.domElement);
    
    // Configurar cámara
    this.camera.position.set(0, 100, 200);
    this.controls.update();
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.05;
    this.controls.screenSpacePanning = false;
    this.controls.minDistance = 10;
    this.controls.maxDistance = 500;
    this.controls.maxPolarAngle = Math.PI / 2;
    
    // Cargar modelos 3D
    this.loadModels();
    
    // Configurar luces
    const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
    this.scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
    directionalLight.position.set(100, 100, 100);
    directionalLight.castShadow = true;
    directionalLight.shadow.mapSize.width = 2048;
    directionalLight.shadow.mapSize.height = 2048;
    directionalLight.shadow.camera.near = 10;
    directionalLight.shadow.camera.far = 500;
    directionalLight.shadow.camera.left = -200;
    directionalLight.shadow.camera.right = 200;
    directionalLight.shadow.camera.top = 200;
    directionalLight.shadow.camera.bottom = -200;
    this.scene.add(directionalLight);
    
    // Añadir cielo
    this.addSky();
    
    // Añadir agua
    this.addWater();
    
    // Añadir terreno
    this.addTerrain();
    
    // Añadir grid para referencia
    this.addGrid();
    
    // Añadir eventos de mouse
    this.setupMouseEvents();
    
    // Iniciar loop de renderizado
    this.animate();
    
    // Manejar redimensionado de ventana
    window.addEventListener('resize', () => this.onWindowResize());
  }
  
  loadModels() {
    // Configurar DRACO loader para modelos comprimidos
    const dracoLoader = new DRACOLoader();
    dracoLoader.setDecoderPath('https://www.gstatic.com/draco/versioned/decoders/1.4.1/');
    
    const gltfLoader = new GLTFLoader();
    gltfLoader.setDRACOLoader(dracoLoader);
    
    // Cargar modelo de dron
    gltfLoader.load(
      'models/drone.glb',
      (gltf) => {
        this.assets.drones.standard = gltf.scene;
        this.assets.drones.standard.scale.set(0.5, 0.5, 0.5);
        
        // Hacer que el modelo reciba y proyecte sombras
        this.assets.drones.standard.traverse((child) => {
          if (child.isMesh) {
            child.castShadow = true;
            child.receiveShadow = true;
          }
        });
        
        console.log('Drone model loaded');
      },
      (xhr) => {
        console.log(`Drone model ${(xhr.loaded / xhr.total * 100)}% loaded`);
      },
      (error) => {
        console.error('Error loading drone model', error);
      }
    );
    
    // Cargar modelo de satélite
    gltfLoader.load(
      'models/satellite.glb',
      (gltf) => {
        this.assets.satellites.standard = gltf.scene;
        this.assets.satellites.standard.scale.set(0.3, 0.3, 0.3);
        
        this.assets.satellites.standard.traverse((child) => {
          if (child.isMesh) {
            child.castShadow = true;
            child.receiveShadow = true;
          }
        });
        
        console.log('Satellite model loaded');
      },
      (xhr) => {
        console.log(`Satellite model ${(xhr.loaded / xhr.total * 100)}% loaded`);
      },
      (error) => {
        console.error('Error loading satellite model', error);
      }
    );
    
    // Cargar modelo de barco
    gltfLoader.load(
      'models/ship.glb',
      (gltf) => {
        this.assets.ships.standard = gltf.scene;
        this.assets.ships.standard.scale.set(0.1, 0.1, 0.1);
        
        this.assets.ships.standard.traverse((child) => {
          if (child.isMesh) {
            child.castShadow = true;
            child.receiveShadow = true;
          }
        });
        
        console.log('Ship model loaded');
      },
      (xhr) => {
        console.log(`Ship model ${(xhr.loaded / xhr.total * 100)}% loaded`);
      },
      (error) => {
        console.error('Error loading ship model', error);
      }
    );
    
    // Cargar modelo de misil
    gltfLoader.load(
      'models/missile.glb',
      (gltf) => {
        this.assets.missiles.standard = gltf.scene;
        this.assets.missiles.standard.scale.set(0.05, 0.05, 0.05);
        
        this.assets.missiles.standard.traverse((child) => {
          if (child.isMesh) {
            child.castShadow = true;
            child.receiveShadow = true;
          }
        });
        
        console.log('Missile model loaded');
      },
      (xhr) => {
        console.log(`Missile model ${(xhr.loaded / xhr.total * 100)}% loaded`);
      },
      (error) => {
        console.error('Error loading missile model', error);
      }
    );
  }
  
  addSky() {
    const sky = new Sky();
    sky.scale.setScalar(10000);
    this.scene.add(sky);
    
    const skyUniforms = sky.material.uniforms;
    
    skyUniforms['turbidity'].value = 10;
    skyUniforms['rayleigh'].value = 2;
    skyUniforms['mieCoefficient'].value = 0.005;
    skyUniforms['mieDirectionalG'].value = 0.8;
    
    const sun = new THREE.Vector3();
    
    const parameters = {
      elevation: 20,
      azimuth: 180
    };
    
    const phi = THREE.MathUtils.degToRad(90 - parameters.elevation);
    const theta = THREE.MathUtils.degToRad(parameters.azimuth);
    
    sun.setFromSphericalCoords(1, phi, theta);
    
    skyUniforms['sunPosition'].value.copy(sun);
  }
  
  addWater() {
    const waterGeometry = new THREE.PlaneGeometry(10000, 10000);
    
    this.water = new Water(
      waterGeometry,
      {
        textureWidth: 512,
        textureHeight: 512,
        waterNormals: new THREE.TextureLoader().load('textures/waternormals.jpg', function (texture) {
          texture.wrapS = texture.wrapT = THREE.RepeatWrapping;
        }),
        sunDirection: new THREE.Vector3(0, 1, 0),
        sunColor: 0xffffff,
        waterColor: 0x001e0f,
        distortionScale: 3.7,
        fog: this.scene.fog !== undefined
      }
    );
    
    this.water.rotation.x = -Math.PI / 2;
    this.water.position.y = -5;
    this.water.receiveShadow = true;
    
    this.scene.add(this.water);
  }
  
  addTerrain() {
    // Simple terrain with perlin noise
    const geometry = new THREE.PlaneGeometry(500, 500, 100, 100);
    geometry.rotateX(-Math.PI / 2);
    
    // Apply height map
    const vertices = geometry.attributes.position.array;
    for (let i = 0; i < vertices.length; i += 3) {
      const x = vertices[i];
      const z = vertices[i + 2];
      
      // Simple perlin noise approximation
      vertices[i + 1] = this.simplex(x * 0.01, z * 0.01) * 10 - 15;
    }
    
    geometry.computeVertexNormals();
    
    const material = new THREE.MeshStandardMaterial({
      color: 0x3d5e3a,
      metalness: 0,
      roughness: 0.8
    });
    
    const terrain = new THREE.Mesh(geometry, material);
    terrain.receiveShadow = true;
    terrain.castShadow = true;
    
    this.scene.add(terrain);
    this.assets.terrain = terrain;
  }
  
  simplex(x, z) {
    // Simple noise function for demo purposes
    // In a real app, use a proper noise library
    return Math.sin(x * 0.5) * Math.cos(z * 0.5) * 0.5 + 0.5;
  }
  
  addGrid() {
    const gridHelper = new THREE.GridHelper(500, 50, 0x444444, 0x222222);
    gridHelper.position.y = -14.9;
    this.scene.add(gridHelper);
  }
  
  setupMouseEvents() {
    this.container.addEventListener('mousemove', (event) => {
      // Calculate mouse position in normalized device coordinates
      const rect = this.container.getBoundingClientRect();
      this.mouse.x = ((event.clientX - rect.left) / this.container.clientWidth) * 2 - 1;
      this.mouse.y = -((event.clientY - rect.top) / this.container.clientHeight) * 2 + 1;
    });
    
    this.container.addEventListener('click', (event) => {
      // Update the picking ray with the camera and mouse position
      this.raycaster.setFromCamera(this.mouse, this.camera);
      
      // Calculate objects intersecting the picking ray
      const intersects = this.raycaster.intersectObjects(this.scene.children, true);
      
      if (intersects.length > 0) {
        // Find the first object that has a trackId property
        for (let i = 0; i < intersects.length; i++) {
          const object = intersects[i].object;
          let current = object;
          
          // Traverse up the parent chain to find an object with trackId
          while (current && !current.userData.trackId) {
            current = current.parent;
          }
          
          if (current && current.userData.trackId) {
            const trackId = current.userData.trackId;
            this.selectTrack(trackId);
            return;
          }
        }
      }
    });
  }
  
  selectTrack(trackId) {
    // Deselect previous track
    if (this.selectedTrack && this.tracks[this.selectedTrack]) {
      const prevObject = this.tracks[this.selectedTrack].object;
      if (prevObject) {
        // Remove highlight effect
        prevObject.traverse((child) => {
          if (child.isMesh && child.material) {
            if (Array.isArray(child.material)) {
              child.material.forEach(mat => {
                mat.emissive.setRGB(0, 0, 0);
              });
            } else {
              child.material.emissive.setRGB(0, 0, 0);
            }
          }
        });
      }
    }
    
    // Select new track
    this.selectedTrack = trackId;
    
    if (this.tracks[trackId]) {
      const object = this.tracks[trackId].object;
      if (object) {
        // Add highlight effect
        object.traverse((child) => {
          if (child.isMesh && child.material) {
            if (Array.isArray(child.material)) {
              child.material.forEach(mat => {
                mat.emissive.setRGB(0.3, 0.3, 0.3);
              });
            } else {
              child.material.emissive.setRGB(0.3, 0.3, 0.3);
            }
          }
        });
        
        // Center camera on selected track
        this.focusOnTrack(trackId);
      }
    }
    
    // Call callback if defined
    if (this.onTrackSelected) {
      this.onTrackSelected(trackId);
    }
  }
  
  focusOnTrack(trackId) {
    if (this.tracks[trackId]) {
      const track = this.tracks[trackId];
      const object = track.object;
      
      if (object) {
        // Get world position of the object
        const position = new THREE.Vector3();
        object.getWorldPosition(position);
        
        // Animate camera to look at the object
        const startPosition = this.camera.position.clone();
        const endPosition = position.clone().add(new THREE.Vector3(50, 30, 50));
        
        const duration = 1000; // ms
        const startTime = Date.now();
        
        const animate = () => {
          const now = Date.now();
          const elapsed = now - startTime;
          const progress = Math.min(elapsed / duration, 1);
          
          // Ease function
          const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);
          const easedProgress = easeOutCubic(progress);
          
          // Interpolate camera position
          this.camera.position.lerpVectors(startPosition, endPosition, easedProgress);
          
          // Make camera look at the object
          this.controls.target.copy(position);
          this.controls.update();
          
          if (progress < 1) {
            requestAnimationFrame(animate);
          }
        };
        
        animate();
      }
    }
  }
  
  updateTracks(tracksData) {
    // Track IDs to remove (tracks that no longer exist)
    const trackIdsToRemove = Object.keys(this.tracks).filter(
      id => !tracksData.some(track => track.id === id)
    );
    
    // Remove tracks that no longer exist
    trackIdsToRemove.forEach(id => {
      this.removeTrack(id);
    });
    
    // Update or add tracks
    tracksData.forEach(trackData => {
      if (this.tracks[trackData.id]) {
        // Update existing track
        this.updateTrack(trackData);
      } else {
        // Add new track
        this.addTrack(trackData);
      }
    });
  }
  
  addTrack(trackData) {
    // Convert position from [lon, lat, alt] to 3D coordinates
    const position = this.geoToPosition(trackData.position);
    
    // Choose model based on track type
    let model = null;
    let rotationOffset = 0;
    
    switch (trackData.type) {
      case 'aircraft':
        if (this.assets.drones.standard) {
          model = this.assets.drones.standard.clone();
          rotationOffset = Math.PI;
        }
        break;
      case 'satellite':
        if (this.assets.satellites.standard) {
          model = this.assets.satellites.standard.clone();
        }
        break;
      case 'vessel':
        if (this.assets.ships.standard) {
          model = this.assets.ships.standard.clone();
        }
        break;
      case 'missile':
        if (this.assets.missiles.standard) {
          model = this.assets.missiles.standard.clone();
        }
        break;
      default:
        // Fallback to simple geometry
        model = this.createDefaultModel(trackData.threatLevel);
        break;
    }
    
    if (!model) {
      model = this.createDefaultModel(trackData.threatLevel);
    }
    
    // Set position
    model.position.copy(position);
    
    // Set rotation based on velocity
    if (trackData.velocity && (trackData.velocity[0] !== 0 || trackData.velocity[1] !== 0)) {
      const direction = Math.atan2(trackData.velocity[0], trackData.velocity[1]);
      model.rotation.y = direction + rotationOffset;
    }
    
    // Add metadata to the model
    model.userData.trackId = trackData.id;
    model.userData.trackType = trackData.type;
    model.userData.threatLevel = trackData.threatLevel;
    
    // Add to scene
    this.scene.add(model);
    
    // Create label
    const label = this.createLabel(trackData);
    model.add(label);
    
    // Store reference
    this.tracks[trackData.id] = {
      data: trackData,
      object: model,
      label: label,
      lastUpdate: Date.now()
    };
    
    // Add trail effect
    this.addTrail(trackData.id, position);
  }
  
  updateTrack(trackData) {
    const track = this.tracks[trackData.id];
    if (!track) return;
    
    // Update stored data
    track.data = trackData;
    track.lastUpdate = Date.now();
    
    // Convert position
    const newPosition = this.geoToPosition(trackData.position);
    
    // Get current position for trail
    const currentPosition = new THREE.Vector3();
    track.object.getWorldPosition(currentPosition);
    
    // Update position with smooth transition
    this.animatePosition(track.object, newPosition);
    
    // Update rotation based on velocity
    if (trackData.velocity && (trackData.velocity[0] !== 0 || trackData.velocity[1] !== 0)) {
      const direction = Math.atan2(trackData.velocity[0], trackData.velocity[1]);
      const rotationOffset = track.data.type === 'aircraft' ? Math.PI : 0;
      this.animateRotation(track.object, new THREE.Euler(0, direction + rotationOffset, 0));
    }
    
    // Update threat level color
    this.updateThreatColor(track);
    
    // Update label
    this.updateLabel(track);
    
    // Update trail
    this.updateTrail(trackData.id, currentPosition, newPosition);
  }
  
  removeTrack(trackId) {
    const track = this.tracks[trackId];
    if (!track) return;
    
    // Remove from scene
    this.scene.remove(track.object);
    
    // Remove trail
    this.removeTrail(trackId);
    
    // Remove from tracks object
    delete this.tracks[trackId];
    
    // If this was the selected track, clear selection
    if (this.selectedTrack === trackId) {
      this.selectedTrack = null;
    }
  }
  
  createDefaultModel(threatLevel) {
    // Create a simple sphere as default model
    const geometry = new THREE.SphereGeometry(2, 16, 16);
    
    // Color based on threat level
    let color;
    switch (threatLevel) {
      case 'high':
        color = 0xff0000;
        break;
      case 'medium':
        color = 0xffaa00;
        break;
      case 'low':
      default:
        color = 0x00ff00;
        break;
    }
    
    const material = new THREE.MeshStandardMaterial({
      color: color,
      metalness: 0.3,
      roughness: 0.6
    });
    
    const sphere = new THREE.Mesh(geometry, material);
    sphere.castShadow = true;
    
    return sphere;
  }
  
  updateThreatColor(track) {
    const threatLevel = track.data.threatLevel;
    let color;
    
    switch (threatLevel) {
      case 'high':
        color = new THREE.Color(0xff0000);
        break;
      case 'medium':
        color = new THREE.Color(0xffaa00);
        break;
      case 'low':
      default:
        color = new THREE.Color(0x00ff00);
        break;
    }
    
    // Apply color to material
    track.object.traverse((child) => {
      if (child.isMesh && child.material) {
        if (Array.isArray(child.material)) {
          // If the model has multiple materials
          child.material.forEach(mat => {
            if (mat.name.includes('highlight') || mat.name.includes('glow')) {
              mat.color.copy(color);
            }
          });
        } else if (child.material.name && (child.material.name.includes('highlight') || child.material.name.includes('glow'))) {
          // Only change color of highlight materials
          child.material.color.copy(color);
        } else if (track.data.type === 'default') {
          // For default models, change the whole color
          child.material.color.copy(color);
        }
      }
    });
  }
  
  createLabel(trackData) {
    // Create canvas for the label
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    canvas.width = 256;
    canvas.height = 128;
    
    // Draw background
    context.fillStyle = 'rgba(0, 0, 0, 0.7)';
    context.fillRect(0, 0, canvas.width, canvas.height);
    
    // Draw border
    context.strokeStyle = this.getThreatColor(trackData.threatLevel);
    context.lineWidth = 4;
    context.strokeRect(2, 2, canvas.width - 4, canvas.height - 4);
    
    // Draw text
    context.font = 'bold 24px Arial';
    context.fillStyle = 'white';
    context.textAlign = 'center';
    context.fillText(trackData.id, canvas.width / 2, 30);
    
    context.font = '18px Arial';
    context.fillText(`Type: ${trackData.type}`, canvas.width / 2, 60);
    context.fillText(`Threat: ${trackData.threatLevel.toUpperCase()}`, canvas.width / 2, 90);
    
    // Create texture from canvas
    const texture = new THREE.CanvasTexture(canvas);
    
    // Create sprite material
    const material = new THREE.SpriteMaterial({
      map: texture,
      transparent: true
    });
    
    // Create sprite
    const sprite = new THREE.Sprite(material);
    sprite.scale.set(20, 10, 1);
    sprite.position.set(0, 15, 0);
    
    return sprite;
  }
  
  updateLabel(track) {
    // Update the label texture
    const sprite = track.label;
    if (!sprite) return;
    
    const canvas = sprite.material.map.image;
    const context = canvas.getContext('2d');
    
    // Clear canvas
    context.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw background
    context.fillStyle = 'rgba(0, 0, 0, 0.7)';
    context.fillRect(0, 0, canvas.width, canvas.height);
    
    // Draw border
    context.strokeStyle = this.getThreatColor(track.data.threatLevel);
    context.lineWidth = 4;
    context.strokeRect(2, 2, canvas.width - 4, canvas.height - 4);
    
    // Draw text
    context.font = 'bold 24px Arial';
    context.fillStyle = 'white';
    context.textAlign = 'center';
    context.fillText(track.data.id, canvas.width / 2, 30);
    
    context.font = '18px Arial';
    context.fillText(`Type: ${track.data.type}`, canvas.width / 2, 60);
    context.fillText(`Threat: ${track.data.threatLevel.toUpperCase()}`, canvas.width / 2, 90);
    
    // Update texture
    sprite.material.map.needsUpdate = true;
  }
  
  getThreatColor(threatLevel) {
    switch (threatLevel) {
      case 'high':
        return 'red';
      case 'medium':
        return 'orange';
      case 'low':
      default:
        return 'green';
    }
  }
  
  geoToPosition(geoPosition) {
    // Convert [lon, lat, alt] to 3D position
    // This is a simple conversion for demonstration
    // In a real app, use a proper geo projection
    const [lon, lat, alt] = geoPosition;
    
    // Scale factors
    const lonScale = 1;
    const latScale = 1;
    
    // Convert to Cartesian coordinates
    const x = lon * lonScale * this.worldScale;
    const z = -lat * latScale * this.worldScale;  // Negative because z is inverted in 3D space
    const y = alt * 0.01 * this.worldScale;  // Scale altitude
    
    return new THREE.Vector3(x, y, z);
  }
  
  animatePosition(object, targetPosition) {
    // Get current position
    const currentPosition = object.position.clone();
    
    // Calculate distance
    const distance = currentPosition.distanceTo(targetPosition);
    
    // If distance is very small, just set position directly
    if (distance < 0.1) {
      object.position.copy(targetPosition);
      return;
    }
    
    // Otherwise animate with lerp
    const duration = 2000; // ms
    const startTime = Date.now();
    
    const animate = () => {
      const now = Date.now();
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Ease function
      const easedProgress = progress;
      
      // Interpolate position
      object.position.lerpVectors(currentPosition, targetPosition, easedProgress);
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    animate();
  }
  
  animateRotation(object, targetRotation) {
    // Get current rotation
    const currentRotation = new THREE.Euler().copy(object.rotation);
    
    // Duration of animation
    const duration = 1000; // ms
    const startTime = Date.now();
    
    const animate = () => {
      const now = Date.now();
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Ease function
      const easedProgress = progress;
      
      // Interpolate rotation
      object.rotation.x = currentRotation.x + (targetRotation.x - currentRotation.x) * easedProgress;
      object.rotation.y = currentRotation.y + (targetRotation.y - currentRotation.y) * easedProgress;
      object.rotation.z = currentRotation.z + (targetRotation.z - currentRotation.z) * easedProgress;
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    animate();
  }
  
  // Trail effect methods
  addTrail(trackId, position) {
    // Create trail geometry
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(600); // 200 points * 3 components
    
    // Fill with initial position
    for (let i = 0; i < 600; i += 3) {
      positions[i] = position.x;
      positions[i + 1] = position.y;
      positions[i + 2] = position.z;
    }
    
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    
    // Get color based on threat level
    const threatLevel = this.tracks[trackId].data.threatLevel;
    let color;
    
    switch (threatLevel) {
      case 'high':
        color = new THREE.Color(0xff0000);
        break;
      case 'medium':
        color = new THREE.Color(0xffaa00);
        break;
      case 'low':
      default:
        color = new THREE.Color(0x00ff00);
        break;
    }
    
    // Create material
    const material = new THREE.LineBasicMaterial({
      color: color,
      transparent: true,
      opacity: 0.7
    });
    
    // Create line
    const trail = new THREE.Line(geometry, material);
    this.scene.add(trail);
    
    // Store reference
    this.tracks[trackId].trail = trail;
  }
  
  updateTrail(trackId, currentPosition, newPosition) {
    const track = this.tracks[trackId];
        if (!track || !track.trail) return;
    
    // Get positions array
    const positions = track.trail.geometry.attributes.position.array;
    
    // Shift all positions back
    for (let i = positions.length - 3; i >= 3; i -= 3) {
      positions[i] = positions[i - 3];
      positions[i + 1] = positions[i - 2];
      positions[i + 2] = positions[i - 1];
    }
    
    // Add new position at the beginning
    positions[0] = newPosition.x;
    positions[1] = newPosition.y;
    positions[2] = newPosition.z;
    
    // Update geometry
    track.trail.geometry.attributes.position.needsUpdate = true;
    
    // Update trail color based on threat level
    const threatLevel = track.data.threatLevel;
    let color;
    
    switch (threatLevel) {
      case 'high':
        color = new THREE.Color(0xff0000);
        break;
      case 'medium':
        color = new THREE.Color(0xffaa00);
        break;
      case 'low':
      default:
        color = new THREE.Color(0x00ff00);
        break;
    }
    
    track.trail.material.color = color;
  }
  
  removeTrail(trackId) {
    const track = this.tracks[trackId];
    if (!track || !track.trail) return;
    
    // Remove from scene
    this.scene.remove(track.trail);
    
    // Dispose geometry and material
    track.trail.geometry.dispose();
    track.trail.material.dispose();
    
    // Remove reference
    delete track.trail;
  }
  
  // Handle window resize
  onWindowResize() {
    this.camera.aspect = this.container.clientWidth / this.container.clientHeight;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
  }
  
  // Animation loop
  animate() {
    requestAnimationFrame(() => this.animate());
    
    // Update water
    if (this.water) {
      this.water.material.uniforms['time'].value += 1.0 / 60.0;
    }
    
    // Update controls
    this.controls.update();
    
    // Update track animations
    this.updateTrackAnimations();
    
    // Render scene
    this.renderer.render(this.scene, this.camera);
  }
  
  updateTrackAnimations() {
    // Update any ongoing animations for tracks
    const now = Date.now();
    
    Object.values(this.tracks).forEach(track => {
      // Skip if no object
      if (!track.object) return;
      
      // Add slight hovering motion for aircraft and satellites
      if (track.data.type === 'aircraft' || track.data.type === 'satellite') {
        const hoverOffset = Math.sin(now * 0.001 + parseInt(track.data.id.replace(/\D/g, '')) * 0.1) * 0.5;
        track.object.position.y += hoverOffset * 0.01;
      }
      
      // Add slight rotation for satellites
      if (track.data.type === 'satellite') {
        track.object.rotation.y += 0.001;
      }
      
      // Bobbing motion for ships
      if (track.data.type === 'vessel') {
        const bobOffset = Math.sin(now * 0.002 + parseInt(track.data.id.replace(/\D/g, '')) * 0.2) * 0.3;
        track.object.rotation.z = bobOffset * 0.05;
      }
    });
  }
  
  // Methods for external control
  setTrackSelectionCallback(callback) {
    this.onTrackSelected = callback;
  }
  
  highlightTrack(trackId) {
    this.selectTrack(trackId);
  }
  
  setCameraPosition(position, lookAt) {
    // Animate camera to new position
    const startPosition = this.camera.position.clone();
    const endPosition = new THREE.Vector3(position.x, position.y, position.z);
    
    const startTarget = this.controls.target.clone();
    const endTarget = new THREE.Vector3(lookAt.x, lookAt.y, lookAt.z);
    
    const duration = 1000; // ms
    const startTime = Date.now();
    
    const animate = () => {
      const now = Date.now();
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Ease function
      const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);
      const easedProgress = easeOutCubic(progress);
      
      // Interpolate camera position and target
      this.camera.position.lerpVectors(startPosition, endPosition, easedProgress);
      this.controls.target.lerpVectors(startTarget, endTarget, easedProgress);
      
      this.controls.update();
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    animate();
  }
  
  resetCamera() {
    this.setCameraPosition(
      { x: 0, y: 100, z: 200 },
      { x: 0, y: 0, z: 0 }
    );
  }
  
  takeScreenshot() {
    // Render the scene
    this.renderer.render(this.scene, this.camera);
    
    // Get image data URL
    const dataURL = this.renderer.domElement.toDataURL('image/png');
    
    return dataURL;
  }
  
  // Toggle visualization modes
  toggleWireframe(enabled) {
    // Toggle wireframe mode for all objects
    this.scene.traverse((object) => {
      if (object.isMesh && object.material) {
        if (Array.isArray(object.material)) {
          object.material.forEach(mat => {
            mat.wireframe = enabled;
          });
        } else {
          object.material.wireframe = enabled;
        }
      }
    });
  }
  
  toggleNightMode(enabled) {
    if (enabled) {
      // Night mode
      this.scene.background = new THREE.Color(0x000011);
      this.scene.fog.color = new THREE.Color(0x000011);
      
      // Adjust lighting
      this.scene.children.forEach(child => {
        if (child.isDirectionalLight) {
          child.intensity = 0.3;
        }
        if (child.isAmbientLight) {
          child.intensity = 0.1;
        }
      });
      
      // Add some stars
      if (!this.stars) {
        const starsGeometry = new THREE.BufferGeometry();
        const starsMaterial = new THREE.PointsMaterial({
          color: 0xffffff,
          size: 1,
          transparent: true
        });
        
        const starsVertices = [];
        for (let i = 0; i < 1000; i++) {
          const x = (Math.random() - 0.5) * 2000;
          const y = (Math.random() - 0.5) * 2000;
          const z = (Math.random() - 0.5) * 2000;
          starsVertices.push(x, y, z);
        }
        
        starsGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starsVertices, 3));
        this.stars = new THREE.Points(starsGeometry, starsMaterial);
        this.scene.add(this.stars);
      }
      
      // Adjust water color
      if (this.water) {
        this.water.material.uniforms['waterColor'].value = new THREE.Color(0x00050a);
      }
    } else {
      // Day mode
      this.scene.background = new THREE.Color(0x000022);
      this.scene.fog.color = new THREE.Color(0x000022);
      
      // Adjust lighting
      this.scene.children.forEach(child => {
        if (child.isDirectionalLight) {
          child.intensity = 1.0;
        }
        if (child.isAmbientLight) {
          child.intensity = 0.5;
        }
      });
      
      // Remove stars
      if (this.stars) {
        this.scene.remove(this.stars);
        this.stars.geometry.dispose();
        this.stars.material.dispose();
        this.stars = null;
      }
      
      // Adjust water color
      if (this.water) {
        this.water.material.uniforms['waterColor'].value = new THREE.Color(0x001e0f);
      }
    }
  }
  
  toggleThermalView(enabled) {
    this.scene.traverse((object) => {
      if (object.isMesh && object.material && !object.userData.isLabel) {
        const materials = Array.isArray(object.material) ? object.material : [object.material];
        
        materials.forEach(material => {
          // Store original material properties if not already stored
          if (enabled && !material.userData.originalProps) {
            material.userData.originalProps = {
              color: material.color ? material.color.clone() : null,
              emissive: material.emissive ? material.emissive.clone() : null,
              map: material.map,
              normalMap: material.normalMap,
              roughnessMap: material.roughnessMap,
              metalnessMap: material.metalnessMap
            };
          }
          
          if (enabled) {
            // Apply thermal shader
            const trackId = object.userData.trackId || (object.parent && object.parent.userData.trackId);
            
            if (trackId && this.tracks[trackId]) {
              const track = this.tracks[trackId];
              let heatLevel = 0;
              
              // Determine heat level based on threat and type
              if (track.data.threatLevel === 'high') {
                heatLevel = 1.0;
              } else if (track.data.threatLevel === 'medium') {
                heatLevel = 0.6;
              } else {
                heatLevel = 0.3;
              }
              
              // Aircraft and missiles are hotter
              if (track.data.type === 'aircraft' || track.data.type === 'missile') {
                heatLevel *= 1.5;
              }
              
              // Apply thermal effect
              material.color.setRGB(heatLevel, heatLevel * 0.5, 0);
              material.emissive.setRGB(heatLevel * 0.5, heatLevel * 0.2, 0);
              
              // Disable textures
              material.map = null;
              material.normalMap = null;
              material.roughnessMap = null;
              material.metalnessMap = null;
            } else {
              // Background objects are cold
              material.color.setRGB(0, 0, 0.2);
              material.emissive.setRGB(0, 0, 0.05);
              
              // Disable textures
              material.map = null;
              material.normalMap = null;
              material.roughnessMap = null;
              material.metalnessMap = null;
            }
          } else if (material.userData.originalProps) {
            // Restore original material properties
            if (material.userData.originalProps.color) {
              material.color.copy(material.userData.originalProps.color);
            }
            
            if (material.userData.originalProps.emissive) {
              material.emissive.copy(material.userData.originalProps.emissive);
            }
            
            material.map = material.userData.originalProps.map;
            material.normalMap = material.userData.originalProps.normalMap;
            material.roughnessMap = material.userData.originalProps.roughnessMap;
            material.metalnessMap = material.userData.originalProps.metalnessMap;
          }
        });
      }
    });
    
    // Adjust scene lighting for thermal view
    this.scene.children.forEach(child => {
      if (child.isDirectionalLight || child.isAmbientLight) {
        child.intensity = enabled ? 0.3 : 1.0;
      }
    });
    
    // Adjust background
    if (enabled) {
      this.scene.background = new THREE.Color(0x000000);
      this.scene.fog.color = new THREE.Color(0x000000);
    } else {
      this.scene.background = new THREE.Color(0x000022);
      this.scene.fog.color = new THREE.Color(0x000022);
    }
  }
}

// React component for integration with the S.I.D.A.S system
import React, { useEffect, useRef, useState } from 'react';
import { Button, ButtonGroup, Form } from 'react-bootstrap';
import './Battlefield3D.css';

const Battlefield3D = ({ tracks, selectedTrackId, onTrackSelect }) => {
  const containerRef = useRef(null);
  const visualizerRef = useRef(null);
  const [viewMode, setViewMode] = useState('normal');
  
  // Initialize 3D visualizer
  useEffect(() => {
    if (containerRef.current && !visualizerRef.current) {
      visualizerRef.current = new Battlefield3DVisualizer('battlefield-container');
      
      // Set track selection callback
      visualizerRef.current.setTrackSelectionCallback((trackId) => {
        if (onTrackSelect) {
          onTrackSelect(trackId);
        }
      });
    }
    
    // Cleanup on unmount
    return () => {
      if (visualizerRef.current) {
        // Cleanup visualizer resources
        // This would be implemented in the visualizer class
      }
    };
  }, [onTrackSelect]);
  
  // Update tracks when they change
  useEffect(() => {
    if (visualizerRef.current && tracks) {
      visualizerRef.current.updateTracks(tracks);
    }
  }, [tracks]);
  
  // Update selected track when it changes
  useEffect(() => {
    if (visualizerRef.current && selectedTrackId) {
      visualizerRef.current.highlightTrack(selectedTrackId);
    }
  }, [selectedTrackId]);
  
  // Handle view mode changes
  useEffect(() => {
    if (!visualizerRef.current) return;
    
    switch (viewMode) {
      case 'wireframe':
        visualizerRef.current.toggleWireframe(true);
        visualizerRef.current.toggleNightMode(false);
        visualizerRef.current.toggleThermalView(false);
        break;
      case 'night':
        visualizerRef.current.toggleWireframe(false);
        visualizerRef.current.toggleNightMode(true);
        visualizerRef.current.toggleThermalView(false);
        break;
      case 'thermal':
        visualizerRef.current.toggleWireframe(false);
        visualizerRef.current.toggleNightMode(false);
        visualizerRef.current.toggleThermalView(true);
        break;
      case 'normal':
      default:
        visualizerRef.current.toggleWireframe(false);
        visualizerRef.current.toggleNightMode(false);
        visualizerRef.current.toggleThermalView(false);
        break;
    }
  }, [viewMode]);
  
  // Handle camera reset
  const handleResetCamera = () => {
    if (visualizerRef.current) {
      visualizerRef.current.resetCamera();
    }
  };
  
  // Handle screenshot
  const handleScreenshot = () => {
    if (visualizerRef.current) {
      const dataURL = visualizerRef.current.takeScreenshot();
      
      // Create temporary link and trigger download
      const link = document.createElement('a');
      link.href = dataURL;
      link.download = `sidas-battlefield-${new Date().toISOString()}.png`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };
  
  return (
    <div className="battlefield-3d">
      <div id="battlefield-container" ref={containerRef} className="battlefield-container"></div>
      
      <div className="battlefield-controls">
        <ButtonGroup>
          <Button 
            variant={viewMode === 'normal' ? 'primary' : 'outline-primary'} 
            onClick={() => setViewMode('normal')}
          >
            Normal
          </Button>
          <Button 
            variant={viewMode === 'night' ? 'primary' : 'outline-primary'} 
            onClick={() => setViewMode('night')}
          >
            Night
          </Button>
          <Button 
            variant={viewMode === 'thermal' ? 'primary' : 'outline-primary'} 
            onClick={() => setViewMode('thermal')}
          >
            Thermal
          </Button>
          <Button 
            variant={viewMode === 'wireframe' ? 'primary' : 'outline-primary'} 
            onClick={() => setViewMode('wireframe')}
          >
            Wireframe
          </Button>
        </ButtonGroup>
        
        <ButtonGroup className="ml-2">
          <Button variant="secondary" onClick={handleResetCamera}>
            Reset Camera
          </Button>
          <Button variant="secondary" onClick={handleScreenshot}>
            Screenshot
          </Button>
        </ButtonGroup>
      </div>
    </div>
  );
};

export default Battlefield3D;

    
