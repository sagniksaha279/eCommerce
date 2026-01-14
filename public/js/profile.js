function showUploadMessage() {
    alert("Profile photo upload feature coming soon!\n\nIn the next update, you'll be able to:\n• Upload new profile pictures\n• Crop and edit your photos\n• Choose from fun avatars\n• Set profile picture visibility");
}

document.addEventListener('DOMContentLoaded', function() {
    const timeElement = document.getElementById('dynamicTime');
    
    function updateLoginTime() {
        const now = new Date();
        const hours = now.getHours();
        const minutes = now.getMinutes();
        
        let timeText = '';
        
        if (hours < 5) {
            timeText = 'Tonight';
        } else if (hours < 12) {
            timeText = 'This morning';
        } else if (hours < 14) {
            timeText = 'Noon';
        } else if (hours < 18) {
            timeText = 'This afternoon';
        } else if (hours < 22) {
            timeText = 'This evening';
        } else {
            timeText = 'Tonight';
        }
        
        const formattedTime = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
        if (timeElement) {
            timeElement.textContent = `${timeText} (${formattedTime})`;
        }
    }
    
    updateLoginTime();
    
    setInterval(updateLoginTime, 60000);
});
function getCurrentLocation() {
    if (!navigator.geolocation) {
        alert("Geolocation is not supported by your browser.");
        return;
    }

    navigator.geolocation.getCurrentPosition(async (position) => {
            const lat = position.coords.latitude;
            const lon = position.coords.longitude;
            const accuracy = position.coords.accuracy;
            try {
                const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`);
                const data = await res.json();
                const address = data.display_name || `${lat}, ${lon}`;

                let message = "We found this address:\n\n" + address;

                if (accuracy > 5000) {
                    message += "\n\n⚠️ Sorry, this location may not be very accurate right now. We're improving this in upcoming updates.";
                }
                message += "\n\nDo you want to use it?";
                const confirmUse = confirm(message);
                if (confirmUse) {
                    document.querySelector('textarea[name="address"]').value = address;
                }
            } catch (err) {
                alert("Unable to fetch address. Please try again.");
            }
        },() => {
            alert("Location permission denied.");
    });
}