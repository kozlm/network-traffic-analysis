import io

from PIL import Image
from folium import Map, Marker
from requests import get


def get_from_api(addr):
    try:
        result = get(f'http://ip-api.com/json/{addr}').json()
        if result['status'] == 'success':
            return result['lat'], result['lon'], result['city'], result['country']
    except:
        pass
    return None


def create_map(ips):
    m = Map(location=[0, 0], zoom_start=2)
    j = {}
    for ip in ips:
        result = get_from_api(ip)
        if not result or not result[0] and not result[1]:
            continue
        lat, lon, city, country = result
        j[ip] = {
            'lat': lat,
            'lon': lon,
            'city': city,
            'country': country,
        }
        Marker(location=[lat, lon]).add_to(m)
    img_data = m._to_png(5)
    img = Image.open(io.BytesIO(img_data))
    img.save('../plots/map.png')
    return j
