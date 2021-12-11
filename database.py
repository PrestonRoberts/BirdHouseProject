from pymongo import MongoClient

mongo_client = MongoClient("mongo")  # docker

# create/get database
db = mongo_client["birdhouse_db"]
user_collection = db["users"]
chats = db["general_chat"]


def collection_exists(name):
    if name in db.list_collection_names():
        return True
    else:
        return False


def insert_document(collection_name, obj):
    obj_col = db[collection_name]
    obj_col.insert_one(obj)


def get_documents(collection_name):
    return list(db[collection_name].find())
