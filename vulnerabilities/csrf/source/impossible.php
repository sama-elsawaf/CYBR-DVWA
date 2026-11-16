<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Check Anti-CSRF token
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Get input
	$pass_curr = $_GET[ 'password_current' ];
	$pass_new  = $_GET[ 'password_new' ];
	$pass_conf = $_GET[ 'password_conf' ];

	// R2: check the current password with Argon2id (prepared statements, constant-time verify)
	$current_user = dvwaCurrentUser();
	$curr_ok = ph_verify_and_upgrade( $db, $current_user, $pass_curr );

	// Do both new passwords match and does the current password match the user?
	if( ( $pass_new === $pass_conf ) && $curr_ok ) {
		// It does!
		$pass_new = ph_hash( $pass_new );   // salted Argon2id, bound as a parameter below

		// Update database with new password
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$current_user = dvwaCurrentUser();
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with passwords matching
		$html .= "<pre>Passwords did not match or current password incorrect.</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
