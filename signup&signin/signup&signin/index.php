<?php
session_start();

$servername = "localhost"; 
$username = "root"; 
$password = ''; 
$dbname = "user_management"; 

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}


$signup_email_error = $signup_password_error = $signup_confirm_password_error = "";
$signin_email_error = $signin_password_error = "";
$signup_success_message = $signin_success_message = "";

$signup_email = $signup_password = $signup_confirm_password = "";
$signin_email = $signin_password = "";

// Function to validate password strength
function isValidPassword($password) {
    return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password);
}

// Handle signup form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['signup-submit'])) {
    $signup_email = trim($_POST['signup-email']);
    $signup_password = trim($_POST['signup-password']);
    $signup_confirm_password = trim($_POST['signup-confirm-password']);

    // Validate email
    if (empty($signup_email) || !filter_var($signup_email, FILTER_VALIDATE_EMAIL)) {
        $signup_email_error = "Invalid email format.";
    } else {
        // Check if email already exists
        $stmt = $conn->prepare("SELECT email FROM user_accounts WHERE email = ?");
        $stmt->bind_param("s", $signup_email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $signup_email_error = "Email already exists.";
        }
        $stmt->close();
    }

    // Validate password
    if (empty($signup_password) || !isValidPassword($signup_password)) {
        $signup_password_error = "Include upper & lower case letters, numbers, symbols.";
    }

    // Validate confirm password
    if ($signup_password !== $signup_confirm_password) {
        $signup_confirm_password_error = "Passwords do not match.";
    }

    // If no errors, proceed with signup
    if (empty($signup_email_error) && empty($signup_password_error) && empty($signup_confirm_password_error)) {
        // Hash the password before storing
        $hashed_password = password_hash($signup_password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO user_accounts (email, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $signup_email, $hashed_password);
        if ($stmt->execute()) {
            $_SESSION['signup_success_message'] = "Signup successful!";
            header("Location: formvalidation.php");
            exit();
        } else {
            echo "Error: " . $stmt->error;
        }
        $stmt->close();
    }
}

// Handle signin form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['signin-submit'])) {
    $signin_email = trim($_POST['signin-email']);
    $signin_password = trim($_POST['signin-password']);

    // Validate email
    if (empty($signin_email) || !filter_var($signin_email, FILTER_VALIDATE_EMAIL)) {
        $signin_email_error = "Invalid email format.";
    }

    // Validate password
    if (empty($signin_password)) {
        $signin_password_error = "Password is required.";
    }

    // If no errors, proceed with signin
    if (empty($signin_email_error) && empty($signin_password_error)) {
        $stmt = $conn->prepare("SELECT password FROM user_accounts WHERE email = ?");
        $stmt->bind_param("s", $signin_email);
        $stmt->execute();
        $stmt->store_result();
        
        // Check if the user exists
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($hashed_password);
            $stmt->fetch();
            // Verify the password
            if (password_verify($signin_password, $hashed_password)) {
                $_SESSION['signin_success_message'] = "Signin successful! Welcome back.";
                header("Location: formvalidation.php"); // Redirect to dashboard
                exit();
            } else {
                $signin_password_error = "Incorrect password.";
            }
        } else {
            $signin_email_error = "No account found with that email.";
        }
        $stmt->close();
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Signup & Signin Form</title>
    <link rel="stylesheet" href="style/styles.css">
    <script src="style/script.js"></script>
</head>
<body>

<div class="container">

    <div id="signup" class="form">
        <h2>Signup</h2>
        <form method="POST" action="">
            <div class="form-group">
                <label for="signup-email">Email:</label>
                <input type="email" name="signup-email" id="signup-email" placeholder="Enter your email" required value="<?php echo htmlspecialchars($signup_email); ?>">
                <div class="signup-error error-message"><?php echo $signup_email_error; ?></div>
            </div>
            <div class="form-group">
                <label for="signup-password">Password:</label>
                <input type="password" name="signup-password" id="signup-password" placeholder="Enter your password" required>
                <div class="signup-error error-message"><?php echo $signup_password_error; ?></div>
            </div>
            <div class="form-group">
                <label for="signup-confirm-password">Confirm Password:</label>
                <input type="password" name="signup-confirm-password" id="signup-confirm-password" placeholder="Confirm your password" required>
                <div class="signup-error error-message"><?php echo $signup_confirm_password_error; ?></div>
            </div>
            <button class="btn" type="submit" name="signup-submit">Sign Up</button>
            <div class="toggle-form">Already have an account? <a href="#" onclick="toggleForms()">Sign In</a></div>
            <?php if (isset($_SESSION['signup_success_message'])): ?>
                <div class="success-message"><?php echo $_SESSION['signup_success_message']; unset($_SESSION['signup_success_message']); ?></div>
            <?php endif; ?>
        </form>
    </div>

    <div id="signin" class="form" style="display:none;">
        <h2>Signin</h2>
        <form method="POST" action="">
            <div class="form-group">
                <label for="signin-email">Email:</label>
                <input type="email" name="signin-email" id="signin-email" placeholder="Enter your email" required value="<?php echo htmlspecialchars($signin_email); ?>">
                <div class="signin-error error-message"><?php echo $signin_email_error; ?></div>
            </div>
            <div class="form-group">
                <label for="signin-password">Password:</label>
                <input type="password" name="signin-password" id="signin-password" placeholder="Enter your password" required>
                <div class="signin-error error-message"><?php echo $signin_password_error; ?></div>
            </div>
            <button class="btn" type="submit" name="signin-submit">Sign In</button>
            <div class="toggle-form">Don't have an account? <a href="#" onclick="toggleForms()">Sign Up</a></div>
            <?php if (isset($_SESSION['signin_success_message'])): ?>
                <div class="success-message"><?php echo $_SESSION['signin_success_message']; unset($_SESSION['signin_success_message']); ?></div>
            <?php endif; ?>
        </form>
    </div>
</div>
</body>
</html>