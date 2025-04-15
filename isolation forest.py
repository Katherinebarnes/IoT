import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from scipy.stats import zscore
from geopy.distance import geodesic

# Function to generate simulated GPS data
def generate_gps_data(n=100):
    np.random.seed(42)
    latitudes = np.random.normal(13.1391, 0.001, n)  # Around Presidency University
    longitudes = np.random.normal(77.6200, 0.001, n)

    # Inject anomalies
    latitudes[-5:] += np.random.normal(0.01, 0.002, 5)
    longitudes[-5:] += np.random.normal(0.01, 0.002, 5)

    return pd.DataFrame({'latitude': latitudes, 'longitude': longitudes})


# Define Safe Zone (Presidency University Bengaluru)
safe_zone_center = {'latitude': 13.1391, 'longitude': 77.6200}
safe_zone_radius_km = 0.1  # 100 meters


# Function to check if a point is within safe zone
def is_within_safe_zone(lat, lon, center, radius_km):
    point = (lat, lon)
    center_point = (center['latitude'], center['longitude'])
    return geodesic(point, center_point).km <= radius_km


# Load GPS data
data = generate_gps_data()

# Z-Score Anomaly Detection
data['z_lat'] = zscore(data['latitude'])
data['z_lon'] = zscore(data['longitude'])
data['z_score'] = np.sqrt(data['z_lat']**2 + data['z_lon']**2)
data['z_anomaly'] = data['z_score'] > 2.5

# Isolation Forest Anomaly Detection
iso_forest = IsolationForest(contamination=0.05, random_state=42)
data['iso_anomaly'] = iso_forest.fit_predict(data[['latitude', 'longitude']]) == -1

# Safe Zone Check
data['in_safe_zone'] = data.apply(lambda row: is_within_safe_zone(
    row['latitude'], row['longitude'], safe_zone_center, safe_zone_radius_km), axis=1)

# Plotting
plt.figure(figsize=(8, 6))

# Plot Normal Data
normal_data = data[~data['iso_anomaly']]
plt.scatter(normal_data['longitude'], normal_data['latitude'],
            c='green', label='Normal', s=30)

# Plot Anomalies
anomalies = data[data['iso_anomaly']]
plt.scatter(anomalies['longitude'], anomalies['latitude'],
            c='red', marker='x', label='Anomaly', s=100)

# Plot Safe Zone Circle
circle = plt.Circle((safe_zone_center['longitude'], safe_zone_center['latitude']),
                    0.001, color='blue', fill=False, linestyle='--', linewidth=2, label='Safe Zone (100m)')

plt.gca().add_patch(circle)

plt.xlabel("Longitude")
plt.ylabel("Latitude")
plt.legend()
plt.title("GPS Anomaly Detection with Safe Zone (Presidency University, Bengaluru)")
plt.show()

# Print Results
print("\nAnomalies Detected (Outside Safe Zone or Anomaly Detected):")
print(data[(data['iso_anomaly'] | data['z_anomaly'] | ~data['in_safe_zone'])][['latitude', 'longitude', 'z_score', 'in_safe_zone']])