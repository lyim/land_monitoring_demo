# data_generator.py
import random
from datetime import datetime
from pymongo import MongoClient, GEO2D

# 配置 MongoDB 本地连接
client = MongoClient("mongodb://localhost:27017/")
db = client["geo_monitoring"]
collection = db["displacement_data"]

# 可选：创建 2D 索引（用于后续地理查询）
collection.create_index([("location", GEO2D)])

def generate_random_point():
    # 北京附近的地理范围
    lon = random.uniform(116.3, 116.5)
    lat = random.uniform(39.8, 40.0)
    return {"type": "Point", "coordinates": [lon, lat]}

def generate_displacement_record():
    return {
        "timestamp": datetime.utcnow(),
        "sensor_id": f"radar-{random.randint(1, 5)}",
        "location": generate_random_point(),
        "displacement": {
            "x": round(random.uniform(-1.0, 1.0), 3),
            "y": round(random.uniform(-1.0, 1.0), 3),
            "z": round(random.uniform(-1.0, 1.0), 3),
        }
    }

if __name__ == "__main__":
    for _ in range(20):  # 插入 20 条记录
        record = generate_displacement_record()
        collection.insert_one(record)
    print("✅ 插入完成")
