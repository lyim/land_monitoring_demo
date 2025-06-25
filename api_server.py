# api_server.py
from fastapi import FastAPI, Query
from typing import List, Optional
from pymongo import MongoClient
from bson import json_util
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
import traceback
from fastapi.responses import Response
from bson import json_util
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi import Depends, HTTPException, status
from fastapi.openapi.utils import get_openapi
import os
from fastapi import UploadFile, File
from s3_utils import upload_file_to_s3

# ==== 安全配置 ====
SECRET_KEY = "your-secret-key-please-change"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ==== 密码哈希器 ====
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==== OAuth2 bearer token schema ====
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==== 用户模型 ====
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "Test User",
        "hashed_password": pwd_context.hash("testpass"),
        "disabled": False
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    full_name: str
    disabled: bool = False

class UserInDB(User):
    hashed_password: str

# ==== 工具函数 ====

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    from datetime import timedelta, datetime
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

app = FastAPI()
# client = MongoClient("mongodb://localhost:27017/")
# client = MongoClient("mongodb://mongo:27017/")
# MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongo:27017/")
client = MongoClient(MONGO_URI)
# collection = client["geo_monitoring"]["displacement_data"]
db = client["geo_monitoring"]
collection = db["displacement_data"]

@app.get("/displacement/recent")
def get_recent_displacement(
    lat: float = Query(..., description="Latitude"),
    lon: float = Query(..., description="Longitude"),
    radius_km: float = Query(1.0, description="Radius in kilometers")
):
    try:
        # 简化：使用 MongoDB 的 $geoWithin/$centerSphere 进行空间查询
        earth_radius_km = 6378.1
        radius_in_radians = radius_km / earth_radius_km

        query = {
            "location": {
                "$geoWithin": {
                    "$centerSphere": [[lon, lat], radius_in_radians]
                }
            }
        }

        results = list(collection.find(query).sort("timestamp", -1).limit(10))
        # to fix error: TypeError: Object of type ObjectId is not JSON serializable
        print("Sample:", results[0])
        # for doc in results:
        #     doc["_id"] = str(doc["_id"])

        # return JSONResponse(content=json_util.loads(json_util.dumps(results)))
        return Response(content=json_util.dumps(results), media_type="application/json")
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/displacement/query")
def query_displacement(
    lat: float = Query(..., description="Latitude"),
    lon: float = Query(..., description="Longitude"),
    radius_km: float = Query(1.0, description="Radius in kilometers"),
    start_time: Optional[str] = Query(None, description="ISO start time (e.g., 2025-06-18T00:00:00Z)"),
    end_time: Optional[str] = Query(None, description="ISO end time"),
    current_user: User = Depends(get_current_user)
):
    earth_radius_km = 6378.1
    radius_in_radians = radius_km / earth_radius_km

    geo_filter = {
        "location": {
            "$geoWithin": {
                "$centerSphere": [[lon, lat], radius_in_radians]
            }
        }
    }

    time_filter = {}
    if start_time or end_time:
        time_filter["timestamp"] = {}
        if start_time:
            time_filter["timestamp"]["$gte"] = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        if end_time:
            time_filter["timestamp"]["$lte"] = datetime.fromisoformat(end_time.replace("Z", "+00:00"))

    query = {**geo_filter, **time_filter}

    results = list(collection.find(query).sort("timestamp", -1).limit(100))
    # return JSONResponse(content=json_util.loads(json_util.dumps(results)))
    return Response(content=json_util.dumps(results), media_type="application/json")

@app.get("/displacement/aggregate")
def aggregate_displacement(
    lat: float = Query(...),
    lon: float = Query(...),
    radius_km: float = Query(1.0),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    earth_radius_km = 6378.1
    radius_in_radians = radius_km / earth_radius_km

    match_stage = {
        "location": {
            "$geoWithin": {
                "$centerSphere": [[lon, lat], radius_in_radians]
            }
        }
    }

    if start_time or end_time:
        match_stage["timestamp"] = {}
        if start_time:
            match_stage["timestamp"]["$gte"] = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        if end_time:
            match_stage["timestamp"]["$lte"] = datetime.fromisoformat(end_time.replace("Z", "+00:00"))

    pipeline = [
        {"$match": match_stage},
        {"$group": {
            "_id": None,
            "avg_x": {"$avg": "$displacement.x"},
            "avg_y": {"$avg": "$displacement.y"},
            "avg_z": {"$avg": "$displacement.z"},
            "count": {"$sum": 1}
        }}
    ]

    result = list(collection.aggregate(pipeline))
    # return JSONResponse(content=json_util.loads(json_util.dumps(result)))
    return Response(content=json_util.dumps(result), media_type="application/json")

@app.get("/stats/average_displacement")
def average_displacement(
    lon: float = Query(..., description="Center longitude"),
    lat: float = Query(..., description="Center latitude"),
    radius: int = Query(1000, description="Radius in meters"),
    minutes: int = Query(60, description="Time window in minutes")
):
    from bson.son import SON

    cutoff_time = datetime.now() - timedelta(minutes=minutes)

    pipeline = [
        {
            "$geoNear": {
                "near": {
                    "type": "Point",
                    "coordinates": [lon, lat]
                },
                "distanceField": "dist.calculated",
                "maxDistance": radius,
                "spherical": True,
                "query": {
                    "timestamp": {"$gte": cutoff_time}
                }
            }
        },
        {
            "$group": {
                "_id": None,
                "avg_x": {"$avg": "$displacement.x"},
                "avg_y": {"$avg": "$displacement.y"},
                "avg_z": {"$avg": "$displacement.z"},
                "count": {"$sum": 1}
            }
        }
    ]

    result = list(collection.aggregate(pipeline))
    if result:
        return {
            "sensor_count": result[0]["count"],
            "avg_displacement": {
                "x": round(result[0]["avg_x"], 3),
                "y": round(result[0]["avg_y"], 3),
                "z": round(result[0]["avg_z"], 3)
            }
        }
    else:
        return {
            "sensor_count": 0,
            "avg_displacement": {
                "x": 0.0,
                "y": 0.0,
                "z": 0.0
            }
        }

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload_file")
def upload_file(file: UploadFile = File(...)):
    file_url = upload_file_to_s3(file.file, file.filename, file.content_type)

    # 存入 Mongo：记录文件名、时间、url
    record = {
        "filename": file.filename,
        "upload_time": datetime.now(),
        "content_type": file.content_type,
        "url": file_url
    }
    db["file_records"].insert_one(record)

    return {
        "message": "File uploaded successfully",
        "url": file_url
    }

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Land Displacement Monitoring API",
        version="1.0.0",
        description="A demo backend for geotechnical IoT monitoring",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    for path in openapi_schema["paths"].values():
        for operation in path.values():
            operation["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi