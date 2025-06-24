# data_generator.py
import random
import time
from datetime import datetime
from pymongo import MongoClient, GEO2D
from pymongo import MongoClient, GEOSPHERE
import os

# 配置 MongoDB 本地连接
# client = MongoClient("mongodb://localhost:27017/")
# 配置 MongoDB 供 docker compose 使用
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongo:27017/")
client = MongoClient(MONGO_URI)
db = client["geo_monitoring"]
collection = db["displacement_data"]

# 可选：创建 2D 索引（用于后续地理查询）
collection.create_index([("location", GEOSPHERE)])

def generate_random_point():
    # 北京附近的地理范围
    lon = random.uniform(116.3, 116.5)
    lat = random.uniform(39.8, 40.0)
    #return {"type": "Point", "coordinates": [lon, lat]}
    return [lon, lat]

def generate_displacement_record():
    return {
        "timestamp": datetime.now(),
        "sensor_id": f"radar-{random.randint(1, 5)}",
        "location": generate_random_point(),
        "displacement": {
            "x": round(random.uniform(-1.0, 1.0), 3),
            "y": round(random.uniform(-1.0, 1.0), 3),
            "z": round(random.uniform(-1.0, 1.0), 3),
        }
    }

if __name__ == "__main__":
    # for _ in range(20):  # 插入 20 条记录
    #     record = generate_displacement_record()
    #     collection.insert_one(record)
    # print("✅ 插入完成")
    # 持续插入数据，随 docker compose 启动
    while True:
        record = generate_displacement_record()
        collection.insert_one(record)
        print(f"✅ Inserted at {record['timestamp']}")
        time.sleep(5)  # 每隔 5 秒插入一条
