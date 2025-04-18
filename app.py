import os
import time
import threading
import secrets # Import the secrets module for generating a strong key
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, LoginRequired, BadPassword, TwoFactorRequired
from flask_session import Session # Import Flask-Session

# --- Flask App Configuration ---
app = Flask(__name__)
# Configure Flask-Session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem" # Store sessions in the filesystem

# Generate a strong, random secret key
# Note: Using environment variables is generally more secure for production
app.config['SECRET_KEY'] = secrets.token_hex(32) # Generated a 32-byte (64 hex characters) random key

Session(app)

# --- Global Variables (for simplicity, consider a more robust state management for production) ---
# Dictionary to hold client instances per session
clients = {}
# Dictionary to hold logs per session
logs = {}
# Dictionary to hold process status per session
processing_status = {} # Use this to indicate if a process is running

# --- Helper Function for Logging ---
def add_log(session_id, message):
    """Adds a timestamped message to the logs for a specific session."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = f"[{timestamp}] {message}"
    logs.setdefault(session_id, []).append(log_entry)
    print(log_entry) # Also print to console for server-side visibility

# --- Routes ---

@app.route('/')
def index():
    """Redirects to the login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    session_id = session.sid
    add_log(session_id, "Accessing login page.")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        add_log(session_id, f"Attempting login for user: {username}")

        client = Client()
        clients[session_id] = client # Store client instance

        try:
            # Attempt to load previous session state if available (optional but good practice)
            # add_log(session_id, "Attempting to load session settings...")
            # client.load_settings(f"session_{username}.json") # Requires saving settings on successful login
            # add_log(session_id, "Session settings load attempted.")

            add_log(session_id, "Calling client.login()...")
            client.login(username, password)
            add_log(session_id, "client.login() completed successfully!") # This log indicates successful login

            # Save session settings on successful login (optional)
            # add_log(session_id, "Attempting to save session settings...")
            # client.dump_settings(f"session_{username}.json")
            # add_log(session_id, "Session settings save attempted.")

            return redirect(url_for('app_page'))

        except (ChallengeRequired, TwoFactorRequired) as e: # Catching both exceptions
            add_log(session_id, f"Login challenge or 2FA required: {type(e).__name__}") # Log the specific exception type
            add_log(session_id, "Account secured. Redirecting to manual resolution page.")
            # Redirect to the challenge page for manual resolution
            return redirect(url_for('challenge_page'))

        except BadPassword:
            add_log(session_id, "Login failed: Bad password.")
            del clients[session_id]
            return render_template('login.html', error="Invalid username or password.")

        except Exception as e:
            add_log(session_id, f"An unexpected error occurred during login: {e}")
            if session_id in clients:
                 del clients[session_id]
            return render_template('login.html', error=f"An error occurred: {e}")

    # GET request - render login form
    return render_template('login.html')

@app.route('/challenge')
def challenge_page():
    """Page instructing the user on how to handle the challenge/2FA manually."""
    session_id = session.sid
    # Updated log message to reflect handling both cases
    add_log(session_id, "Displaying manual challenge/2FA resolution instructions.")
    return render_template('challenge.html')

@app.route('/continue_login', methods=['POST'])
def continue_login():
    """Attempts to finalize login after user resolves the challenge/2FA manually."""
    session_id = session.sid
    client = clients.get(session_id)

    if not client:
        add_log(session_id, "No client found for session. Redirecting to login.")
        return redirect(url_for('login'))

    # Updated log message
    add_log(session_id, "User confirmed manual resolution. Attempting to continue login.")

    try:
        add_log(session_id, "Calling client.get_self_info() to check session status...")
        # Instagrapi's Client object should retain the challenge/2FA state.
        # Attempting a simple API call should trigger the final login step
        # if the user has successfully unsecured the account manually.
        client.get_self_info() # This should succeed if the challenge/2FA is passed
        add_log(session_id, "client.get_self_info() successful! Login is now complete.")

        add_log(session_id, "Login continued successfully!")
        # Save session settings on successful login (optional)
        # add_log(session_id, "Attempting to save session settings...")
        # client.dump_settings(f"session_{client.username}.json") # Requires username attribute
        # add_log(session_id, "Session settings save attempted.")


        return redirect(url_for('app_page'))

    except Exception as e:
        add_log(session_id, f"Failed to continue login after manual resolution: {e}")
        if session_id in clients:
            del clients[session_id] # Clean up client instance
        return render_template('login.html', error=f"Failed to continue login. Please try logging in again. Error: {e}")


@app.route('/app')
def app_page():
    """Main application page for data extraction and messaging."""
    session_id = session.sid
    client = clients.get(session_id)

    if not client:
        add_log(session_id, "Client not found for session. Redirecting to login.")
        return redirect(url_for('login'))

    add_log(session_id, "Accessing main application page.")
    return render_template('app.html')

@app.route('/start_process', methods=['POST'])
def start_process():
    """Starts the data extraction and messaging process in a background thread."""
    session_id = session.sid
    client = clients.get(session_id)

    if not client:
        add_log(session_id, "Client not found for session. Cannot start process.")
        return jsonify({"status": "error", "message": "Not logged in."})

    if processing_status.get(session_id):
         add_log(session_id, "Process already running for this session.")
         return jsonify({"status": "info", "message": "Process already running."})


    target_username = request.form.get('target_username')
    extract_type = request.form.get('extract_type') # 'followers' or 'following'
    message_text = request.form.get('message_text')
    message_count = int(request.form.get('message_count', 0))
    message_delay = int(request.form.get('message_delay', 0))

    if not target_username or not extract_type or not message_text or message_count <= 0 or message_delay < 0:
        add_log(session_id, "Invalid input received for starting process.")
        return jsonify({"status": "error", "message": "Invalid input."})

    add_log(session_id, f"Received request to process user '{target_username}' ({extract_type}).")

    # Set processing status
    processing_status[session_id] = True

    # Run the process in a background thread to avoid blocking the Flask app
    thread = threading.Thread(target=process_instagram_data, args=(session_id, client, target_username, extract_type, message_text, message_count, message_delay))
    thread.start()

    return jsonify({"status": "success", "message": "Process started."})

def process_instagram_data(session_id, client, target_username, extract_type, message_text, message_count, message_delay):
    """Background function to perform extraction and messaging."""
    add_log(session_id, f"Starting background process for {target_username} ({extract_type}).")
    try:
        # 1. Get User ID
        add_log(session_id, f"Fetching user ID for {target_username}...")
        try:
            target_user = client.user_info_by_username(target_username)
            target_user_id = target_user.pk
            add_log(session_id, f"User ID for {target_username}: {target_user_id}")
        except Exception as e:
            add_log(session_id, f"Error fetching user ID for {target_username}: {e}")
            processing_status[session_id] = False # Reset status
            return # Stop process

        # 2. Extract Followers or Following
        user_list = []
        if extract_type == 'followers':
            add_log(session_id, f"Fetching followers for {target_username}...")
            try:
                # instagrapi can fetch followers in batches
                user_list = client.user_followers(target_user_id, amount=message_count)
                add_log(session_id, f"Fetched {len(user_list)} followers.")
            except Exception as e:
                add_log(session_id, f"Error fetching followers: {e}")
                processing_status[session_id] = False # Reset status
                return # Stop process

        elif extract_type == 'following':
            add_log(session_id, f"Fetching following for {target_username}...")
            try:
                # instagrapi can fetch following in batches
                user_list = client.user_following(target_user_id, amount=message_count)
                add_log(session_id, f"Fetched {len(user_list)} following.")
            except Exception as e:
                add_log(session_id, f"Error fetching following: {e}")
                processing_status[session_id] = False # Reset status
                return # Stop process

        # Limit the list to message_count if more were fetched
        users_to_message = user_list[:message_count]
        add_log(session_id, f"Preparing to message {len(users_to_message)} users.")

        # 3. Send Messages
        add_log(session_id, f"Starting messaging process with a delay of {message_delay} seconds...")
        for i, user in enumerate(users_to_message):
            if not processing_status.get(session_id): # Check if process was cancelled (not implemented in UI yet)
                 add_log(session_id, "Process cancelled.")
                 break

            try:
                add_log(session_id, f"Messaging user {i+1}/{len(users_to_message)}: {user.username} (ID: {user.pk})")
                client.direct_send(message_text, user_ids=[user.pk])
                add_log(session_id, f"Message sent to {user.username}.")
            except Exception as e:
                add_log(session_id, f"Error sending message to {user.username}: {e}")
                # Continue with the next user even if one fails

            if i < len(users_to_message) - 1: # Don't delay after the last message
                add_log(session_id, f"Waiting for {message_delay} seconds...")
                time.sleep(message_delay)

        add_log(session_id, "Messaging process finished.")

    except Exception as e:
        add_log(session_id, f"An error occurred during the background process: {e}")

    finally:
        processing_status[session_id] = False # Reset status
        add_log(session_id, "Background process concluded.")


@app.route('/get_logs')
def get_logs():
    """Returns the current logs for the session."""
    session_id = session.sid
    return jsonify(logs.get(session_id, []))

@app.route('/logout')
def logout():
    """Logs out the user and clears session data."""
    session_id = session.sid
    add_log(session_id, "Logging out.")
    if session_id in clients:
        try:
            # Optional: Perform instagrapi logout if available and necessary
            # clients[session_id].logout()
            pass # instagrapi Client might not have an explicit logout that invalidates session server-side
        except Exception as e:
            add_log(session_id, f"Error during client logout: {e}")
        del clients[session_id]
    if session_id in logs:
        del logs[session_id]
    if session_id in processing_status:
        del processing_status[session_id]

    session.clear() # Clear Flask session data
    add_log(session_id, "Session cleared. Redirecting to login.")
    return redirect(url_for('login'))


# --- Run the App ---
if __name__ == '__main__':
    # Use 0.0.0.0 to make the server accessible externally for Render
    # Use a hardcoded port as requested, instead of an environment variable
    app.run(debug=True, host='0.0.0.0', port=5000)
