<?php
session_start();
$conn = new mysqli("localhost", "root", "", "user_auth");
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$signup_msg = '';
$login_msg = '';
$popup_msg = '';
$popup_type = '';

// SIGNUP Process
if (isset($_POST['signup'])) {
    $username = htmlspecialchars(trim($_POST['username']));
    $email = htmlspecialchars(trim($_POST['email']));
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Check if any field is empty
    if (
        strlen($username) === 0 ||
        strlen($email) === 0 ||
        strlen($password) === 0 ||
        strlen($confirm_password) === 0
    ) {
        $signup_msg = "All fields are required.";
        $popup_msg = $signup_msg;
        $popup_type = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $signup_msg = "Invalid email format.";
        $popup_msg = $signup_msg;
        $popup_type = 'error';
    } elseif ($password !== $confirm_password) {
        $signup_msg = "Passwords do not match.";
        $popup_msg = $signup_msg;
        $popup_type = 'error';
    } else {
        $check = $conn->prepare("SELECT id FROM users WHERE email = ? OR username = ?");
        $check->bind_param("ss", $email, $username);
        $check->execute(); $check->store_result();

        if ($check->num_rows > 0) {
            $signup_msg = "Username or Email already exists.";
            $popup_msg = $signup_msg;
            $popup_type = 'error';
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $email, $hashed_password);
            if ($stmt->execute()) {
                $signup_msg = "Signup successful! Please login.";
                $popup_msg = $signup_msg;
                $popup_type = 'success';
            } else {
                $signup_msg = "Signup failed.";
                $popup_msg = $signup_msg;
                $popup_type = 'error';
            }
            $stmt->close();
        }
        $check->close();
    }
}

// LOGIN Process
if (isset($_POST['login'])) {
    $username_email = htmlspecialchars(trim($_POST['username_email']));
    $password = $_POST['password'];

    if (empty($username_email) || empty($password)) {
        $login_msg = "All fields are required.";
        $popup_msg = $login_msg;
        $popup_type = 'error';
    } else {
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE email = ? OR username = ?");
        $stmt->bind_param("ss", $username_email, $username_email);
        $stmt->execute(); $stmt->store_result();

        if ($stmt->num_rows == 1) {
            $stmt->bind_result($id, $username, $hashed_password);
            $stmt->fetch();
            if (password_verify($password, $hashed_password)) {
                $_SESSION['user'] = $username;
                header("Location:index.html");
                exit();
            } else {
                $login_msg = "Incorrect username/email or password.";
                $popup_msg = $login_msg;
                $popup_type = 'error';
            }
        } else {
            $login_msg = "User does not exist.";
            $popup_msg = $login_msg;
            $popup_type = 'error';
        }
        $stmt->close();
    }
}
$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
<title>Authentication System</title>
<style>
body {
    font-family: 'Segoe UI', sans-serif;
    background: #fff5f7;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
}
.container {
    background: #fff;
    padding: 30px 24px 20px 24px;
    border-radius: 16px;
    width: 320px;
    box-shadow: 0 0 18px rgba(255,105,180,0.10);
    border: 2px solid #ffdee9;
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}
h2 {
    text-align: center;
    margin-bottom: 18px;
    color: #ff69b4;
    font-size: 2em;
    font-weight: bold;
}
input[type="text"], input[type="email"], input[type="password"] {
    width: 91.5%;
    padding: 10px 12px;
    margin-bottom: 14px;
    border-radius: 8px;
    border: 1.5px solid #ffdee9;
    background: #fff0f5;
    font-size: 1em;
    transition: border 0.2s;
}
input[type="text"]:focus, input[type="email"]:focus, input[type="password"]:focus {
    border: 1.5px solid #ff69b4;
    outline: none;
    background: #fff;
}
button {
    width: 100%;
    padding: 12px;
    background-color: #ff69b4;
    color: white;
    border: none;
    border-radius: 25px;
    font-size: 1em;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.3s;
    margin-top: 5px;
}
button:hover {
    background-color: #ff1493;
}

.toggle {
    text-align: center;
    margin-top: 14px;
}
.toggle a {
    color: #ff69b4;
    text-decoration: none;
    font-weight: 500;
}
.toggle a:hover {
    text-decoration: underline;
    color: #ff1493;
}
.popup-modal {
    display: none;
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: #fff0f5;
    border: 2px solid #ff69b4;
    border-radius: 12px;
    box-shadow: 0 4px 24px rgba(255,105,180,0.15);
    padding: 22px 28px 18px 28px;
    min-width: 220px;
    z-index: 10;
    text-align: center;
    animation: popIn 0.25s;
}
@keyframes popIn {
    from { opacity: 0; transform: translateX(-50%) scale(0.9);}
    to { opacity: 1; transform: translateX(-50%) scale(1);}
}
.popup-modal.success {
    border-color: #4cd964;
    background: #eafff2;
    color: #2e7d32;
}
.popup-modal.error {
    border-color: #ff69b4;
    background: #fff0f5;
    color: #ff1493;
}
.popup-modal .close-btn {
    margin-top: 10px;
    background: #ff69b4;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 6px 18px;
    font-size: 1em;
    cursor: pointer;
    transition: background 0.2s;
}
.popup-modal .close-btn:hover {
    background: #ff1493;
}
@media (max-width: 500px) {
    .container { width: 98vw; padding: 10vw 2vw; }
    h2 { font-size: 1.3em; }
    .popup-modal { min-width: 120px; padding: 12px 8px 10px 8px; }
}
</style>
</head>
<body>

<div class="container" id="signup-form">
    <?php if ($popup_msg && isset($_POST['signup'])): ?>
        <div class="popup-modal <?php echo $popup_type; ?>" id="popupModal" style="display:block;">
            <?php echo htmlspecialchars($popup_msg); ?>
            <br>
            <button class="close-btn" onclick="closePopup()">OK</button>
        </div>
        <script>
        // Prevent form resubmission on reload
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
        // Keep modal open until OK is clicked
        document.body.style.pointerEvents = "none";
        document.getElementById('popupModal').style.pointerEvents = "auto";
        </script>
    <?php endif; ?>
    <h2>Signup</h2>
    <form method="POST" autocomplete="off">
        <input type="text" name="username" placeholder="Username" required value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
        <input type="email" name="email" placeholder="Email" required value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
        <input type="password" name="password" placeholder="Password" required>
        <input type="password" name="confirm_password" placeholder="Confirm Password" required>
        <button type="submit" name="signup">Signup</button>
    </form>
    <div class="toggle">Already have an account? <a href="#login">Login</a></div>
</div>

<div class="container" id="login-form" style="display:none;">
    <?php if ($popup_msg && isset($_POST['login'])): ?>
        <div class="popup-modal <?php echo $popup_type; ?>" id="popupModal2" style="display:block;">
            <?php echo htmlspecialchars($popup_msg); ?>
            <br>
            <button class="close-btn" onclick="closeLoginPopup()">OK</button>
        </div>
        <script>
        // Prevent form resubmission on reload
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
        // Keep modal open until OK is clicked
        document.body.style.pointerEvents = "none";
        document.getElementById('popupModal2').style.pointerEvents = "auto";
        </script>
    <?php endif; ?>
    <h2>Login</h2>
    <form method="POST" autocomplete="off">
        <input type="text" name="username_email" placeholder="Username or Email" required value="<?php echo isset($_POST['username_email']) ? htmlspecialchars($_POST['username_email']) : ''; ?>">
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" name="login">Login</button>
    </form>
    <div class="toggle">Don't have an account? <a href="#signup">Signup</a></div>
</div>

<script>
const signupForm = document.getElementById('signup-form');
const loginForm = document.getElementById('login-form');
function showForm() {
    if (window.location.hash === '#login') {
        signupForm.style.display = 'none';
        loginForm.style.display = 'block';
    } else {
        signupForm.style.display = 'block';
        loginForm.style.display = 'none';
    }
}
window.addEventListener('hashchange', showForm);
window.addEventListener('load', showForm);

// Popup modal close logic
function closePopup() {
    var popup = document.getElementById('popupModal');
    if (popup) popup.style.display = 'none';
    document.body.style.pointerEvents = "auto";
}

function closeLoginPopup() {
    var popup = document.getElementById('popupModal2');
    if (popup) popup.style.display = 'none';
    document.body.style.pointerEvents = "auto";
}
</script>
</body>
</html>
