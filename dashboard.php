<?php
session_start();

if(isset($_SESSION['user_id']) && isset($_SESSION['username'])) {
    ?>

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>User Dashboard - Election Calgary Online</title>
        <style>
            body {
                font-family: 'Arial', sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
                line-height: 1.6;
            }
            .header {
                background-color: #0056b3;
                color: #fff;
                text-align: center;
                padding: 10px 0;
            }
            .container {
                width: 80%;
                margin: 20px auto;
                padding: 20px;
                background-color: #fff;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            h2, h3 {
                color: #333;
            }
            section {
                margin-bottom: 20px;
                padding: 10px;
                border-bottom: 1px solid #ddd;
            }
            a {
                color: #0056b3;
                text-decoration: none;
            }
            
            .vote-button, button {
		    background-color: #4CAF50; /* Green */
		    border: none;
		    color: white;
		    padding: 15px 32px;
		    text-align: center;
		    text-decoration: none;
		    display: inline-block;
		    font-size: 16px;
		    margin: 4px 2px;
		    cursor: pointer;
		}

		.vote-button:hover, button:hover {
		    background-color: #45a049;
		}

            
            a:hover {
                text-decoration: underline;
            }
            .logout-link {
                display: block;
                margin-top: 20px;
                text-align: right;
                padding-right: 20px;
            }
            footer {
                background-color: #333;
                color: #fff;
                text-align: center;
                padding: 10px 0;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Election Calgary Online - User Dashboard</h1>
        </div>

        <div class="container">
            <h1>Welcome, <?php echo $_SESSION['first_name']; ?></h1>

            <section id="current-polls">
                <h3>Current Polls</h3>
                <!-- [Insert dynamic PHP code to list current polls] -->
                <button onclick="window.location.href='Vote.html'">Go to Vote</button>
            </section>

            <section id="voting-history">
                <h3>Voting History</h3>
                <!-- [Insert dynamic PHP code to display voting history] -->
                
            </section>

            <section id="upcoming-polls">
                <h3>Upcoming Polls</h3>
                <!-- [Insert dynamic PHP code to list upcoming polls] -->
            </section>

            <section id="notifications">
                <h3>Notifications</h3>
                <!-- [Dynamic notifications] -->
            </section>

            <section id="account-management">
                <h3>Account Management</h3>
                <a href="edit_profile.php">Edit Profile</a>
                <!-- [Additional links] -->
            </section>

            <div class="logout-link">
                <a href="logout.php">Logout</a>
            </div>
        </div>

        <footer>
            <p>&copy; <?php echo date("Y"); ?> Election Calgary Online</p>
        </footer>
    </body>
    </html>

    <?php
} else {
    header("Location: login.php");
    exit();
}
?>

