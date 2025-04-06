const map = L.map('map', {
  zoomSnap: 0.5,
  zoomDelta: 0.5, 
  scrollWheelZoom: true,
  attributionControl: true
}).setView([20, 80], 2);

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/">CARTO</a>',
  subdomains: 'abcd',
  maxZoom: 19
}).addTo(map);

const markerClusterGroup = L.markerClusterGroup({
  showCoverageOnHover: true,
  spiderfyOnMaxZoom: true,
  zoomToBoundsOnClick: true,
  maxClusterRadius: 50 
});
map.addLayer(markerClusterGroup);


const markerCache = new Map();

function addMarker(lat, lng, popupText, iconUrl) {
  const key = `${lat},${lng}`;
    if (markerCache.has(key)) return;
  const customIcon = L.icon({
      iconUrl: iconUrl || '/static/assets/white-hacker-male-svgrepo-com.svg', 
      iconSize: [38, 95],
      iconAnchor: [22, 94],
      popupAnchor: [-3, -76]
  });

  const marker = L.marker([lat, lng], { icon: customIcon })
      .addTo(markerClusterGroup)
      .bindPopup(popupText);

  marker.on('mouseover', () => marker.openPopup()); 
  markerCache.set(key, marker);
  return marker;
}


function removeOldMarkers(timeout = 30000) {
  const now = Date.now();
  markerCache.forEach((marker, key) => {
      const markerTime = marker.timestamp || now;
      if (now - markerTime > timeout) {
          map.removeLayer(marker);
          markerCache.delete(key);
      }
  });
}
setInterval(removeOldMarkers, 10000);

// Define custom styles
const neonGlowStyle = {
  color: 'white',
  weight: 3,
  opacity: 0.8,
  lineJoin: 'round',
  className: 'neon-glow' // CSS class for glowing effect
};

// CSS for glowing effect
const style = document.createElement('style');
style.textContent = `
  .neon-glow {
    filter: drop-shadow(0 0 1px white);
  }
  .dash-animation {
    stroke-dasharray: 10;
    animation: dash-move 2s linear infinite;
  }
  @keyframes dash-move {
    from {
      stroke-dashoffset: 10;
    }
    to {
      stroke-dashoffset: 0;
    }
  }
`;
document.head.appendChild(style);

function addAnimatedCircle(lat, lng) {
  const circle = L.circle([lat, lng], {
      color: 'white',
      fillColor: '#f03',
      fillOpacity: 0.5,
      radius: 50000 
  }).addTo(map);

  let grow = true;
  setInterval(() => {
      const currentRadius = circle.getRadius();
      circle.setRadius(grow ? currentRadius + 500 : currentRadius - 500);
      if (currentRadius >= 60000) grow = false;
      else if (currentRadius <= 40000) grow = true;
  }, 300);
}

function fetchLatestData() {
  fetch('/get_latest_data')
      .then(response => {
          if (!response.ok) {
              throw new Error('Network response was not ok');
          }
          return response.json();
      })
      .then(data => {
          console.log('Fetched data:', data);
          data.forEach(item => {
              const { latitude, longitude, City, Country } = item;
              addMarker(latitude, longitude, `${City}, ${Country}`, 'https://i.ibb.co/4dXskZL/custom-icon.png');
              addAnimatedCircle(latitude, longitude);
              const { latitude: fromLat, longitude: fromLng, City2, Country2 } = item;
              addSciFiTrace(fromLat, fromLng, latitude, longitude); 
          });
      })
      .catch(error => console.error('Error fetching latest data:', error));
}

const eventSource = new EventSource('http://127.0.0.1:5050/stream');
eventSource.onmessage = function (event) {
  const data = JSON.parse(event.data);
  console.log('Received data:', data);
  data.forEach(item => {
      const { latitude, longitude, City, Country } = item;
      addMarker(latitude, longitude, `${City}, ${Country}`);
      addAnimatedCircle(latitude, longitude);
      getCurrentPosition((my_lat, my_lng) => {
        traceCurrentPosition(latitude, longitude, my_lat, my_lng);
      });

  });
};

eventSource.onerror = function (event) {
  console.error('Error with EventSource:', event);
};

document.addEventListener('DOMContentLoaded', fetchLatestData);


function addSciFiTrace(fromLat, fromLng, toLat, toLng) {
  // Base polyline
  const polyline = L.polyline([[fromLat, fromLng], [toLat, toLng]], neonGlowStyle).addTo(map);

  // Animate dashes using SVG
  const path = polyline._path; // Access the underlying SVG path
  path.classList.add('dash-animation');
}

function highlightCurrentLocation(lat, lng) {
  const hitmark = L.circle([lat, lng], {
    color: 'white',
    fillColor: 'white',
    fillOpacity: 0.7,
    radius: 100
  }).addTo(map);

  let grow = true;
  setInterval(() => {
    const currentRadius = hitmark.getRadius();
    hitmark.setRadius(grow ? currentRadius + 50 : currentRadius - 50);
    if (currentRadius >= 200) grow = false;
    else if (currentRadius <= 100) grow = true;
  }, 300);

  map.setView([lat, lng], 10);
}

function traceCurrentPosition(currentLat, currentLng, receiverLat, receiverLng) {
  // Add a line for tracing
  const traceLine = L.polyline([[currentLat, currentLng], [receiverLat, receiverLng]], neonGlowStyle).addTo(map);

  // Animate the trace movement
  const traceIcon = L.divIcon({
    className: 'trace-icon',
    html: '<div style="width: 10px; height: 10px; background: red; border-radius: 50%;"></div>',
    iconSize: [10, 10]
  });

  const traceMarker = L.marker([currentLat, currentLng], { icon: traceIcon }).addTo(map);

  let currentStep = 0;
  const totalSteps = 100;
  const stepLat = (receiverLat - currentLat) / totalSteps;
  const stepLng = (receiverLng - currentLng) / totalSteps;

  const interval = setInterval(() => {
    if (currentStep >= totalSteps) {
      clearInterval(interval);
      return;
    }
    currentLat += stepLat;
    currentLng += stepLng;
    traceMarker.setLatLng([currentLat, currentLng]);
    currentStep++;
  }, 50);
}



function getCurrentPosition(callback) {
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords;
        console.log(`Current Position: Lat ${latitude}, Lng ${longitude}`);
        callback(latitude, longitude);
      },
      (error) => {
        console.error('Error getting location:', error.message);
        alert('Unable to fetch your location. Please allow location access.');
      },
      {
        enableHighAccuracy: true, // Use GPS for more accurate results
        timeout: 10000, // Timeout after 10 seconds
        maximumAge: 0 // Prevent caching of old results
      }
    );
  } else {
    alert('Geolocation is not supported by your browser.');
  }
}