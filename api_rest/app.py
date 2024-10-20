from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory storage for users
users = []

# Route to get the list of users
@app.route('/users', methods=['GET'])
def get_users():
    return jsonify(users)

# Route to add a new user
@app.route('/users', methods=['POST'])
def add_user():
    user = request.get_json()
    users.append(user)
    return jsonify(user), 201

if __name__ == '__main__':
    app.run(debug=True)