import os
import sys
# make sure we can import from backend
sys.path.insert(0, os.path.dirname(__file__))

from services.origin_service import create_origin, get_origins_for_user, get_origin, update_origin, delete_origin
import uuid

def run_tests():
    test_user_id = "test-user-id-123"
    
    print("Testing create_origin...")
    try:
        origin = create_origin(test_user_id, "Test Origin", "127.0.0.1", 8080)
        print("Created:", origin)
    except Exception as e:
        print("Failed create:", e)
        return
        
    origin_id = origin["id"]
    
    print("Testing get_origins_for_user...")
    origins = get_origins_for_user(test_user_id)
    print(f"Found {len(origins)} origins for user")
    
    print("Testing get_origin...")
    fetched = get_origin(origin_id)
    print("Fetched:", fetched)
    
    print("Testing update_origin...")
    update_origin(origin_id, label="Updated Origin", port=9090)
    updated = get_origin(origin_id)
    print("Updated:", updated)
    
    print("Testing delete_origin...")
    delete_origin(origin_id)
    print("Deleted successfully.")
    
    origins_after_delete = get_origins_for_user(test_user_id)
    print(f"Found {len(origins_after_delete)} origins after deletion.")

if __name__ == "__main__":
    run_tests()
