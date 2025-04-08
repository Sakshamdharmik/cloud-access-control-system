Capability-Based Access Control System
This project implements a capability-based access control system intended to secure cloud-based resources using a microservice-oriented architecture. It is based on a model proposed in a referenced research paper and focuses on cloud security by using capability tokens for authorization.
The system is developed in Python using the Flask web framework and is composed of two separate microservices:

1. Cloud Server (app.py): This component handles user registration, object creation, and capability token generation. It provides APIs that allow users to register themselves, define cloud objects, and request access tokens.

2. Resource Server (resource_server.py): This microservice verifies capability tokens and grants or denies access to requested resources based on the token’s validity and permissions.

The system uses a local SQLite database (capability.db), which is automatically generated when the application is run. The project is fully testable using Postman, and a sample Postman collection (postman_collection.json) is included for convenience.

Project Folder Structure:
- app.py (Cloud Server)
- resource_server.py (Resource Server)
- database/ (Folder where capability.db is stored)
- requirements.txt (Python dependencies)
- postman_collection.json (Postman API testing file)
- README.md (This documentation)

Steps to Run the Project:

1. Clone the GitHub repository using:
   git clone https://github.com/Sakshamdharmik/cloud-access-control-system
2. Navigate into the project directory:
   cd capability-access-control-system

3. (Optional) Create a virtual environment:
   python -m venv venv

4. Activate the virtual environment:
   - On Windows: venv\Scripts\activate
   - On Unix/macOS: source venv/bin/activate

5. Install required Python libraries:
   pip install -r requirements.txt

6. Run the Cloud Server in one terminal:
   python app.py
   (This will start the server at http://localhost:5000)

7. Run the Resource Server in another terminal:
   python resource_server.py
   (This will start the server at http://localhost:6000)

Testing with Postman:
Import the file postman_collection.json into Postman. It contains preconfigured API requests. The main API endpoints are:

- POST /register: Register a user
- POST /add-object: Create a cloud object
- POST /generate-token: Generate a capability token for a user
- POST /access-resource: Used by the Resource Server to grant or deny access based on the token
- POST /revoke-token: Revoke an existing token and deny future access

All data exchanged with the APIs should be in JSON format.

Use Case and Relevance:
This project is ideal for academic demonstrations or assignments focused on cloud computing and security. It is especially suited for illustrating access control mechanisms like capability-based models in a cloud environment.
