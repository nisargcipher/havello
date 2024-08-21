<?php

namespace Voxel;

if (!defined('ABSPATH')) {
  exit;
}

function is_debug_mode()
{
  return defined('WP_DEBUG') && WP_DEBUG;
}

function is_dev_mode()
{
  return defined('VOXEL_DEV_MODE') && VOXEL_DEV_MODE;
}

function is_running_tests()
{
  return defined('VOXEL_RUNNING_TESTS') && VOXEL_RUNNING_TESTS;
}

require_once locate_template('app/utils/utils.php');

require_once(ABSPATH . 'wp-admin/includes/user.php');

include(ABSPATH . "wp-includes/pluggable.php");

foreach (\Voxel\config('controllers') as $controller) {
  new $controller;
}




class myapiendpoints
{

  function __construct()
  {
    add_action('rest_api_init', array($this, 'uheme_routes'));
  }

  function uheme_routes()
  {
    register_rest_route(
      'Voxel/v1',
      '/hello',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'apifi'),
      )
    );
  }

  public function apifi()
  {
    return "working";
  }
}
$myapiendpoints = new myapiendpoints();


class userpost
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'user_post'));
  }

  function user_post()
  {
    register_rest_route(
      'Voxel/v1',
      '/user-reg',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'userreg'),
      )
    );

    register_rest_route(
      'Voxel/v1',
      '/verify-code',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'verify_code'),
      )
    );

    register_rest_route(
      'Voxel/v1',
      '/resend-code',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'resend_code'),
      )
    );
  }

  function userreg(\WP_REST_Request $request)
  {
    $user_data = $request->get_params();

    // Check if email already exists
    if (email_exists($user_data['user_email'])) {
      return array('message' => 'Email and user is already in use');
    }

    // Generate a confirmation code and send email
    $confirmation_code = \Voxel\random_string(5);
    $this->send_confirmation_code($user_data['user_login'], $user_data['user_email'], $confirmation_code);

    // Store user data temporarily, maybe in a transient or custom table
    set_transient('user_registration_' . $user_data['user_login'], $user_data, 15 * MINUTE_IN_SECONDS);

    // Return response indicating verification is required
    return array(
      'success' => true,
      'message' => 'Verification code sent to your email.',
      'verification_required' => true,
    );
  }

  function send_confirmation_code($user_login, $email, $code)
  {
    global $wpdb;

    $subject = _x('Account confirmation', 'auth', 'voxel');
    $message = sprintf(_x('Your confirmation code is %s', 'auth', 'voxel'), $code);

    // Store confirmation code in the database
    $wpdb->query($wpdb->prepare(
      "DELETE FROM {$wpdb->prefix}voxel_auth_codes WHERE user_login = %s",
      $user_login
    ));
    $wpdb->query($wpdb->prepare(
      "INSERT INTO {$wpdb->prefix}voxel_auth_codes (`user_login`, `code`, `created_at`) VALUES (%s, %s, %s)",
      $user_login,
      $code,
      date('Y-m-d H:i:s', current_time('timestamp', 0))
    ));

    // Send email
    wp_mail($email, $subject, \Voxel\email_template($message), [
      'Content-type: text/html;',
    ]);
  }

  function verify_code(\WP_REST_Request $request)
  {
    $params = $request->get_params();
    $user_login = sanitize_user($params['user_login']);
    $code = sanitize_text_field($params['code']);

    try {
      $this->verify_confirmation_code($user_login, $code);

      // Retrieve temporarily stored user data
      $user_data = get_transient('user_registration_' . $user_login);
      if (!$user_data) {
        throw new \Exception(__('Registration data not found or expired. Please register again.', 'voxel'));
      }

      // Create user
      $user_id = wp_insert_user(array(
        'user_login' => $user_data['user_login'],
        'user_email' => $user_data['user_email'],
        'user_pass' => $user_data['user_pass'],
        'display_name' => $user_data['first_name'] . ' ' . $user_data['last_name'],
        'roles' => 'Subscriber',
      ));

      if (is_wp_error($user_id)) {
        $error_message = strip_tags($user_id->get_error_message());
        return array('message' => $error_message);
      }

      // Clear transient after successful registration
      delete_transient('user_registration_' . $user_login);

      return array(
        'message' => 'User created successfully',
        'user_id' => $user_id,
        'user_data' => $user_data,
      );
    } catch (\Exception $e) {
      return array(
        'message' => $e->getMessage(),
      );
    }
  }

  function verify_confirmation_code($user_login, $code)
  {
    global $wpdb;

    $code = $wpdb->get_row($wpdb->prepare(
      "SELECT `created_at` FROM {$wpdb->prefix}voxel_auth_codes WHERE `user_login` = %s AND `code` = %s",
      $user_login,
      $code
    ));

    if (!$code) {
      throw new \Exception(__('Code verification failed.', 'voxel'));
    }

    $created_at = strtotime($code->created_at ?? '');
    if (!$created_at) {
      throw new \Exception(__('Please try again.', 'voxel'));
    }

    // Check if code is expired (10 minutes expiry)
    if (($created_at + (10 * MINUTE_IN_SECONDS)) < time()) {
      throw new \Exception(__('Verification code expired. Please request a new one.', 'voxel'));
    }

    // Code verified, remove from database
    $wpdb->delete(
      $wpdb->prefix . 'voxel_auth_codes',
      array('user_login' => $user_login, 'code' => $code),
      array('%s', '%s')
    );
  }

  function resend_code(\WP_REST_Request $request)
  {
    global $wpdb;
    $params = $request->get_params();
    $user_login = sanitize_user($params['user_login']);

    try {
      // Retrieve user data from transient
      $user_data = get_transient('user_registration_' . $user_login);
      if (!$user_data) {
        throw new \Exception(__('User data not found. Please try registering again.', 'voxel'));
      }

      // Retrieve the existing confirmation code from the database
      // $code = $wpdb->get_var($wpdb->prepare(
      //   "SELECT `code` FROM {$wpdb->prefix}voxel_auth_codes WHERE `user_login` = %s",
      //   $user_login
      // ));

      $confirmation_code = \Voxel\random_string(5);

      // Send the new confirmation email
      $this->send_confirmation_code($user_data['user_login'], $user_data['user_email'], $confirmation_code);

      return array(
        'success' => true,
        'message' => 'Existing verification code sent to your email.',
      );
    } catch (\Exception $e) {
      return array(
        'message' => $e->getMessage(),
      );
    }
  }
}

$userpost = new userpost();

class usercheck
{

  function __construct()
  {
    add_action('rest_api_init', array($this, 'user_post'));
  }
  function user_post()
  {
    register_rest_route(
      'Voxel/v1',
      '/user-check',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'check'),

      )
    );
  }
  function check(\WP_REST_Request $request)
  {
    $user_data = $request->get_params();
    if (username_exists($user_data['user_login'])) {
      return array('message' => 'Username  is already in use');
    }
    else{
      return array('message'=>'successfully');
    }
  }
}
$usercheck = new usercheck();

class gologin
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'gologin'));
  }
  function gologin()
  {
    register_rest_route(
      'Voxel/v1',
      '/gologin',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'userreg'),

      )
    );
  }
  function verify_google_token($token)
  {
    $client = new Google_Client(['client_id' => 'YOUR_GOOGLE_CLIENT_ID']);
    $payload = $client->verifyIdToken($token);
    if ($payload) {
      $userid = $payload['sub'];
      // Token is valid, return user ID
      return $userid;
    } else {
      // Token is invalid, return false or handle error
      return false;
    }
  }
  function userreg()
  {
    $token = $request->get_param('token');
    $userid = verify_google_token($token);
    if ($userid) {
      // Check if user exists
      $user = get_user_by('login', 'google_' . $userid);
      if (!$user) {
        // User doesn't exist, create a new user
        $userdata = array(
          'user_login' => 'google_' . $userid,
          'user_email' => 'user@example.com', // Use a valid email
          'first_name' => 'as',
          'last_name' => 'Doe',
          'role' => 'subscriber', // Set the role as needed
        );
        $user_id = wp_insert_user($userdata);
        if (!is_wp_error($user_id)) {
          $error_code =  $user_id->get_error_code();
          $error_message = Strip_tags($user_id->get_error_message());
          return array('message' => 'User created successfully', $userdata);
        } else {
          $error_code = $user->get_error_code();
          $error_message = Strip_tags($user->get_error_message());
          return new \WP_Error('user_creation_failed', __($error_message, 'text-domain'), array('status' => $error_code));
        }
      } else {
        return new \WP_Error('user_creation_failed', __('Email and user is already in use', 'text-domain'), array('status' => 400));
      }
    } else {
      return new \WP_Error('user_creation_failed', __('Token verification failed,', 'text-domain'), array('status' => 400));
    }
  }
}



class updateuser
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'updateuser'));
  }

  function updateuser()
  {
    register_rest_route(
      'Voxel/v1',
      '/updateuser/(?P<id>\d+)',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'update'),
        // 'permission_callback' => function ($request) {
        //   return is_user_logged_in(); // Ensure user is logged in to update user data
        // },

      )
    );
  }
  function update($request)
  {
    $user_id = $request->get_param('id');
    $user_data = $request->get_params();

    // Check if the current user has permission to update the specified user
    // if (get_current_user_id() != $user_id && !current_user_can('edit_users')) {
    //     return new \WP_Error('user_update_failed', 'You do not have permission to update this user.', array('status' => 403));
    // }

    // Update user data
    $updated_user_data = array();

    if (isset($user_data['user_login'])) {
      $updated_user_data['user_login'] = $user_data['user_login'];
    }

    if (isset($user_data['user_email'])) {
      $updated_user_data['user_email'] = $user_data['user_email'];
    }

    if (isset($user_data['user_pass'])) {
      $updated_user_data['user_pass'] = $user_data['user_pass'];
    }

    $updated_user = wp_update_user(array_merge(['ID' => $user_id], $updated_user_data));

    if (is_wp_error($updated_user)) {
      $error_code = $updated_user->get_error_code();
      $error_message = strip_tags($updated_user->get_error_message());
      return new \WP_Error('user_update_failed', $error_message, array('status' => $error_code));
    }

    return array('message' => 'User updated successfully', 'user_id' => $user_id);
  }
}
$updateuser = new updateuser();



function generate_random_token()
{
  return wp_generate_password(24, false);
}
class login
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'login'));
  }
  function login()
  {
    register_rest_route(
      'Voxel/v1',
      '/login',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'loginuser'),

      )
    );
  }
  function loginuser($request)
  {
    $user_data = $request->get_params();


    if (!isset($user_data['user_email']) || !isset($user_data['user_pass'])) {
      return new \WP_Error('missing_credentials', 'Useremail and password are required.', array('status' => 400));
    }

    $username = sanitize_text_field($user_data['user_email']);
    $password = sanitize_text_field($user_data['user_pass']);

    $user = wp_authenticate($username, $password);

    if (is_wp_error($user)) {
      $error_code = $user->get_error_code();
      $error_message = Strip_tags($user->get_error_message());
      return new \WP_Error('invalid_credentials', $error_message, array('status' => $error_code));
    }

    $token = generate_random_token();
    wp_set_current_user($user->ID, $user->user_login);
    do_action('wp_login', $user->user_login, $user);
    update_user_meta($user->ID, 'custom_reset_token', $token);

    // User successfully authenticated
    return array(
      'message' => 'User logged in successfully.',
      'user_id' => $user->ID,
      'user_email' => $user->user_email,
      'token' => $token,
    );
  }
}
$user = new login();
// Api for get all user
class getallu
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'getallu'));
  }
  function getallu()
  {
    register_rest_route(
      'Voxel/v1',
      '/getallu',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $per_page = $request->get_param('per_page') ? intval($request->get_param('per_page')) : 5;
    $page = $request->get_param('page') ? intval($request->get_param('page')) : 1;

    // Calculate offset based on pagination parameters
    $offset = ($page - 1) * $per_page;
     // Get total number of users
    $total_users = count_users()['total_users'];

    // Calculate total pages
    $total_pages = ceil($total_users / $per_page);
    // If the requested page is beyond the total pages, return an empty array
    if ($page > $total_pages) {
      return array(
        'user_data' => [],
        'total_pages' => $total_pages
      );
    }
    $users = get_users(array(
    'number' => $per_page,
    'offset' => $offset,));

    
    if (empty($users)) {
      return new \WP_Error('no_users_found', 'No user found.', array('status' => 404));
    }
    
    $user_data = array();
    foreach ($users as $user) {
      $user_id = $user->ID;
      $user_name = $user->display_name;
      $profile_pic_url = get_avatar_url($user_id);
      $bio = get_the_author_meta('description', $user_id);
      $location = get_user_meta($user_id, 'location', true);

      $user_data[] = array(
        'id' => $user_id,
        'name' => $user_name,
        'profile_pic_url' => $profile_pic_url,
        'bio' => $bio,
      );
    }

    // Return the formatted response with total pages
    return rest_ensure_response(array(
      'user_data' => $user_data,
      'total_pages' => $total_pages
    ));
  }
}
$getallu = new getallu();


class deleteu
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'deleteu'));
  }
  function deleteu()
  {
    register_rest_route(
      'Voxel/v1',
      '/deleteu/(?P<id>\d+)',
      array(
        'methods' => 'DELETE',
        'callback' => array($this, 'deleteuser'),
      )
    );
  }

  function deleteuser($request)
  {
    $user_id = $request->get_param('id');
    try {
      if (!wp_delete_user($user_id)) {
        throw new Exception('Failed to delete user.');
      }
      return array('message' => 'User deleted successfully');
    } catch (Exception $e) {
      return new \WP_Error('user_delete_failed', $e->getMessage(), array('status' => 500));
    }
  }
}
$deleteuser = new deleteu();

class passup
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'passres'));
  }
  function passres()
  {
    register_rest_route(
      'Voxel/v1',
      '/passres',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'pass'),
        'permission_callback' => 'is_user_logged_in',

      )
    );
  }

  function pass($request)
  {
    $user_data = $request->get_params();
    if (empty($user_data['user_pass']) || empty($user_data['new_password'])) {
      return new \WP_Error('missing_data', 'Current password and new password are required.', array('status' => 400));
    }

    $user = wp_get_current_user();
    // Check if the current password is correct
    $current_password = sanitize_text_field($user_data['user_pass']);
    if (!wp_check_password($current_password, $user->user_pass, $user->ID)) {
      return new \WP_Error('invalid_current_password', 'Current password is incorrect.', array('status' => 401));
    }

    // Update the user's password
    $new_password = sanitize_text_field($user_data['user_pass']);
    wp_set_password($new_password, $user->ID);

    return array(
      'message' => 'Password updated successfully.',
    );
  }
}
$passup = new passup();


class UserPasswordRecovery
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    function register_routes()
    {
        register_rest_route(
            'Voxel/v1',
            '/forgot-password',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'forgot_password'),
            )
        );

        register_rest_route(
            'Voxel/v1',
            '/reset-password',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'reset_password'),
            )
        );

        register_rest_route(
            'Voxel/v1',
            '/resend-code-pass',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'resend_code'),
            )
        );

        register_rest_route(
            'Voxel/v1',
            '/verify-code-pass',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'verify_code'),
            )
        );
    }

    function forgot_password(\WP_REST_Request $request)
    {
        $params = $request->get_params();
        $user_email = sanitize_email($params['email']);
        $user = get_user_by('email', $user_email);

        if (!$user) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => __('Email not found', 'voxel'),
            ));
        }

        $code = \Voxel\random_string(5);
        $subject = _x('Account recovery', 'auth', 'voxel');
        $message = sprintf(_x('Your recovery code is %s', 'auth', 'voxel'), $code);

        wp_mail($user_email, $subject, \Voxel\email_template($message), [
            'Content-type: text/html;',
        ]);

        update_user_meta($user->ID, 'voxel:recovery', wp_slash(wp_json_encode([
            'code' => password_hash($code, PASSWORD_DEFAULT),
            'expires' => time() + (2 * MINUTE_IN_SECONDS),
        ])));

        return new \WP_REST_Response(array(
            'success' => true,
            'message' => 'Recovery code sent to your email.',
        ));
    }

    function resend_code(\WP_REST_Request $request)
    {
        $params = $request->get_params();
        $user_email = sanitize_email($params['email']);
        $user = get_user_by('email', $user_email);

        if (!$user) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => __('Email not found', 'voxel'),
            ));
        }

        $recovery = json_decode(get_user_meta($user->ID, 'voxel:recovery', true), ARRAY_A);

        if (!$recovery || empty($recovery['code']) || empty($recovery['expires'])) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => __('No recovery code found. Please initiate the forgot password process.', 'voxel'),
            ));
        }

        $code = \Voxel\random_string(5);
        $subject = _x('Account recovery', 'auth', 'voxel');
        $message = sprintf(_x('Your recovery code is %s', 'auth', 'voxel'), $code);

        wp_mail($user_email, $subject, \Voxel\email_template($message), [
            'Content-type: text/html;',
        ]);

        update_user_meta($user->ID, 'voxel:recovery', wp_slash(wp_json_encode([
            'code' => password_hash($code, PASSWORD_DEFAULT),
            'expires' => time() + (2 * MINUTE_IN_SECONDS),
        ])));

        return new \WP_REST_Response(array(
            'success' => true,
            'message' => 'Recovery code resent to your email.',
        ));
    }

    function verify_code(\WP_REST_Request $request)
    {
        $params = $request->get_params();
        $user_email = sanitize_email($params['email']);
        $code = sanitize_text_field($params['code']);
        $user = get_user_by('email', $user_email);

        if (!$user) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => __('Email not found', 'voxel'),
            ));
        }

        $recovery = json_decode(get_user_meta($user->ID, 'voxel:recovery', true), ARRAY_A);
        if (!is_array($recovery) || empty($recovery['code']) || empty($recovery['expires'])) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => __('Invalid request.', 'voxel'),
            ));
        }

        if ($recovery['expires'] < time()) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => _x('Recovery session has expired.', 'auth', 'voxel'),
            ));
        }

        if (!password_verify($code, $recovery['code'])) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => _x('Code is not correct.', 'auth', 'voxel'),
            ));
        }

        return new \WP_REST_Response(array(
            'success' => true,
            'message' => 'Code verified successfully.',
        ));
    }

    function reset_password(\WP_REST_Request $request)
    {
        $params = $request->get_params();
        $user_email = sanitize_email($params['email']);
        $new_password = sanitize_text_field($params['new_password']);
        $user = get_user_by('email', $user_email);

        if (!$user) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => __('Email not found', 'voxel'),
            ));
        }

        // Reset password
        wp_set_password($new_password, $user->ID);

        // Delete recovery code after successful reset
        delete_user_meta($user->ID, 'voxel:recovery');

        return new \WP_REST_Response(array(
            'success' => true,
            'message' => 'Password reset successfully.',
        ));
    }
}

$UserPasswordRecovery =new UserPasswordRecovery();


//Api for get all place
class allpost
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'allpost'));
  }
  function allpost()
  {
    register_rest_route(
      'Voxel/v1',
      '/allpost',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $per_page = $request->get_param('per_page') ? intval($request->get_param('per_page')) : 5;
    $page = $request->get_param('page') ? intval($request->get_param('page')) : 1;

    $offset = ($page - 1) * $per_page; 
     // Get total number of posts
    $total_posts = wp_count_posts('places')->publish;

    // Calculate total pages
    $total_pages = ceil($total_posts / $per_page);
    // If the requested page is beyond the total pages, return an empty array
    if ($page > $total_pages) {
      return array(
        'formatted_posts' => [],
        'total_pages' => $total_pages
      );
    }
    $posts = get_posts(array(
      'post_type' => 'places',
      'post_status' => 'publish',
      'posts_per_page' => $per_page, // Get all posts//-1(for all)
      'offset'=> $offset,
    ));

    if (empty($posts)) {
      return new \WP_Error('no_posts_found', 'No posts found.', array('status' => 404));
    }


    $formatted_posts = array();

    foreach ($posts  as $posts) {
      $featured_image_id = get_post_thumbnail_id($posts->ID);
      $featured_image_url = '';
      if ($featured_image_id) {
        $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
        if (is_array($featured_image_data)) {
          $featured_image_url = $featured_image_data[0];
        }
      }

      $profile_logo_id = get_post_meta($posts->ID, 'logo', true);
      $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';
      $address = get_post_meta($posts->ID, 'location', true);
      $address_data = json_decode($address, true);
      $review_stats_json = get_post_meta($posts->ID, 'voxel:review_stats', true);
      if ($review_stats_json) {
        $review_stats = json_decode($review_stats_json, true); // Decode the JSON to an associative array

        $total_reviews = $review_stats['total'] ?? 0; // Using null coalescing operator to provide default value
        $average_rating = isset($review_stats['average'])  ? round($review_stats['average'] + 3, 2) : ''; // Defaulting to '0' if not set
      }
      // Extract the desired components
      $address = isset($address_data['address']) ? $address_data['address'] : '';
      $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
      $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';
      $opening_hours_data = get_post_meta($posts->ID, 'work-hours', true);
      $opening_hours = json_decode($opening_hours_data, true);
  
      $formatted_opening_hours = array();
      if (!empty($opening_hours) && is_array($opening_hours)) {
        foreach ($opening_hours as $hours_data) {
          $days = $hours_data['days'] ?? array();
          $status = $hours_data['status'] ?? 'hours';
          $hours = $hours_data['hours'] ?? array();
          foreach ($days as $day) {
            if (!isset($formatted_opening_hours[$day])) {
              $formatted_opening_hours[$day] = array();
            }
            if ($status === 'closed') {
              $formatted_opening_hours[$day][] = 'Closed all day';
            } elseif ($status === 'appointments_only') {
              $formatted_opening_hours[$day][] = 'Appointments Only';
            }elseif (!empty($hours)) {
              foreach ($hours as $hour) {
                $formatted_opening_hours[$day][] = $hour['from'] . '-' . $hour['to'];
              }
            } else {
              // If no hours are provided, indicate that it's open all day
              $formatted_opening_hours[$day][] = 'Open all day';
            }
          }
        }
      }
      $formatted_posts[] = array(
        'id' => $posts->ID,
        'name' => $posts->post_title,
        'content' => $posts->post_content,
        'featured_image_url' => $featured_image_url,
        'profile_logo_url' => $profile_logo_url,
        'address' => $address,
        'latitude' => $latitude,
        'longitude' => $longitude,
        'Total Reviews' => $total_reviews,
        'Average Rating' =>  $average_rating,
        'opening_hours' => $formatted_opening_hours,
      );
    }
     return array(
        'formatted_posts' => $formatted_posts,
        'total_pages' => $total_pages
    );
  }
}
$allpost = new allpost();
//for palce by id
class postget
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'postget'));
  }
  function postget()
  {
    register_rest_route(
      'Voxel/v1',
      '/postget/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $post_id = $request->get_param('id');
    $post = get_post($post_id);

    if (!$post || $post->post_status !== 'publish') {
      return new \WP_Error('invalid_post_id', 'Invalid post ID', array('status' => 404));
    }

    $featured_image_url = '';
    $featured_image_id = get_post_thumbnail_id($post->ID);
    if ($featured_image_id) {
      $featured_image_url = wp_get_attachment_url($featured_image_id);
    }

    $profile_image_url = '';
    $profile_image_id = get_post_meta($post->ID, 'logo', true);
    if ($profile_image_id) {
      $profile_image_url = wp_get_attachment_url($profile_image_id);
    }
    // var_dump($profile_image_url);
    // die;
    $gallery_images = array();
    $gallery_ids = get_post_meta($post->ID, 'gallery', true);

    if ($gallery_ids) {
      $gallery_ids_array = explode(',', $gallery_ids);
      foreach ($gallery_ids_array as $gallery_id) {
        $gallery_image_url = wp_get_attachment_url($gallery_id);
        if ($gallery_image_url) {
          $gallery_images[] = $gallery_image_url;
        }
      }
    }
    $meta_data = array();
    $meta_data = get_post_meta($post->ID);
    $voxel_verified = isset($meta_data['voxel:verified'][0]) && $meta_data['voxel:verified'][0] == '1' ? true : false;
    $meta_data_json = get_post_meta($post_id, 'voxel:review_stats', true);
    $meta_review_array = json_decode($meta_data_json, true) ?? '';
    // var_dump($meta_review_array['by_score']['1']);
    // die;
    $categories_review = array(
    //'total'=> isset($meta_review_array['total']) ? $meta_review_array['total'] + 3 : null, $meta_review_array['by_score']['1'] ?? null,
    'average'=> isset($meta_review_array['average']) ? $meta_review_array['average'] + 3 : null,
    'total_people'=>isset($meta_review_array['total']) ? $meta_review_array['total'] : null,  
    'overall' => isset($meta_review_array['by_category']['score']) ? $meta_review_array['by_category']['score'] + 3 : null,
    'service' => isset($meta_review_array['by_category']['custom-660']) ? $meta_review_array['by_category']['custom-660'] + 3 : null,
    'hospitality' => isset($meta_review_array['by_category']['custom-978']) ? $meta_review_array['by_category']['custom-978'] + 3 : null,
    'pricing' => isset($meta_review_array['by_category']['custom-271']) ? $meta_review_array['by_category']['custom-271'] + 3 : null,
    );
    foreach ($meta_data as $key => $value) {
      $meta_data[$key] = maybe_unserialize($value[0]);
    }
    $repeater= array();
    $repeater= get_post_meta($post->ID);
    foreach ($repeater as $key => $value) {
      $repeater[$key] = maybe_unserialize(json_decode($value[0]));
    }
    $repeater_data = array();
    $formatted_data_socail = array(); // This will store the formatted result

   if (isset($repeater['repeater-2']) && is_array($repeater['repeater-2'])) {
   foreach ($repeater['repeater-2'] as $item) {
    if (isset($item->taxonomy, $item->url) && is_array($item->taxonomy)) {
      foreach ($item->taxonomy as $taxonomy) {
                // Create a key using the taxonomy and associate it with the URL
        $formatted_data_socail[$taxonomy . '_url'] = $item->url;
      }
    }
    }
   }
    global $wpdb;
    $query = "
    SELECT 
        t.*,
        r.id AS reply_id,
        r.user_id AS reply_user_id,
        r.parent_id AS reply_parent_id,
        r.content AS reply_content,
        r.details AS reply_details,
        r.created_at AS reply_created_at,
        r.edited_at AS reply_edited_at,
        l.user_id AS like_user_id,
        l.status_id AS like_status_id,
        rl.user_id AS reply_like_user_id,
        rl.reply_id AS reply_like_reply_id
    FROM
        {$wpdb->prefix}voxel_timeline t
    LEFT JOIN {$wpdb->prefix}voxel_timeline_replies r ON t.id = r.status_id
    LEFT JOIN wp_voxel_timeline_likes l ON t.id = l.status_id
    LEFT JOIN wp_voxel_timeline_reply_likes rl ON r.id = rl.reply_id
    WHERE
        t.post_id = %d
    ORDER BY
        t.created_at DESC, r.created_at ASC
";

    $timeline_data = $wpdb->get_results($wpdb->prepare($query, $post_id));
    // print_r($timeline_data);
    // die;
    
$timeline_entries = array();
$replies_added = array(); // Track replies added to prevent duplicates

foreach ($timeline_data as $entry) {
    // Process statuses
    if (!isset($timeline_entries[$entry->id])) {
        $user_info = get_userdata($entry->user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $details = !empty($entry->details) ? json_decode($entry->details, true) : array();
        $attachment_urls = array();
        if (isset($details['files'])) {
            $file_ids = explode(',', $details['files']);
            foreach ($file_ids as $file_id) {
                $file_url = wp_get_attachment_url($file_id);
                if ($file_url) {
                    $attachment_urls[] = $file_url;
                }
            }
        }

        // Process review score adjustments
        $meta_review_array = isset($details['rating']) ? isset($details['rating']): array();
        // print_r($details['rating']['score']);
        // die();
        $review_score_adjusted = array(
            'overall' => isset($details['rating']['score']) ? $details['rating']['score'] + 3 : null,
            'service' => isset($details['rating']['custom-660']) ? $details['rating']['custom-660'] + 3 : null,
            'hospitality' => isset($details['rating']['custom-978']) ? $details['rating']['custom-978'] + 3 : null,
            'pricing' => isset($details['rating']['custom-271']) ? $details['rating']['custom-271'] + 3 : null
        );
        $timeline_entries[$entry->id] = array(
            'id' => $entry->id,
            'user_id' => $entry->user_id,
            'profile_pic' => get_avatar_url($entry->user_id),
            'user_name' => $user_name,
            'published_as' => $entry->published_as,
            'post_id' => $entry->post_id,
            'content' => $entry->content,
            'details' => $attachment_urls,
            'review_score_adjusted' => $review_score_adjusted,
            'review_score' => isset($entry->review_score) ? $entry->review_score+3 : null,
            'created_at' => $entry->created_at,
            'edited_at' => $entry->edited_at,
            'replies' => array(),
            'likes' => array(),
            'reply_likes' => array(),
            'like_count' => 0,
        );
    }

    // Process likes
    if ($entry->like_user_id && !isset($timeline_entries[$entry->id]['likes'][$entry->like_user_id])) {
        $user_info = get_userdata($entry->like_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['likes'][$entry->like_user_id] = array(
            'like_user_id' => $entry->like_user_id,
            'like_user_name' => $user_name,
            'like_status_id' => $entry->like_status_id
        );
        $timeline_entries[$entry->id]['like_count']++;
    }

    // Process replies
    if ($entry->reply_id && !isset($replies_added[$entry->reply_id])) {
        $user_info = get_userdata($entry->reply_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $reply_details = !empty($entry->reply_details) ? json_decode($entry->reply_details, true) : array();
        $reply_to = isset($reply_details['reply_to']) ? $reply_details['reply_to'] : null;

        $reply_data = array(
            'reply_id' => $entry->reply_id,
            'reply_parent_id' => $entry->reply_parent_id,
            'reply_user_id' => $entry->reply_user_id,
            'reply_user_name' => $user_name,
            'reply_profile_pic' => get_avatar_url($entry->reply_user_id),
            'reply_content' => $entry->reply_content,
            'reply_details' => $reply_details,
            'reply_created_at' => $entry->reply_created_at,
            'reply_edited_at' => $entry->reply_edited_at,
            'reply_likes_count' => 0,
            'replies' => array()
        );
        $replies_added[$entry->reply_id] = $reply_data;

        if ($reply_to && isset($timeline_entries[$entry->id]['replies'][$reply_to])) {
            $timeline_entries[$entry->id]['replies'][$reply_to]['replies'][] = $reply_data;
        } elseif ($entry->reply_parent_id && isset($timeline_entries[$entry->reply_parent_id]['replies'])) {
            $timeline_entries[$entry->reply_parent_id]['replies'][] = $reply_data;
        } else {
            $timeline_entries[$entry->id]['replies'][] = $reply_data;
        }
    }

    // Process reply likes
    if ($entry->reply_like_user_id && !isset($timeline_entries[$entry->id]['reply_likes'][$entry->reply_like_user_id])) {
        $user_info = get_userdata($entry->reply_like_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['reply_likes'][$entry->reply_like_user_id] = array(
            'reply_like_user_id' => $entry->reply_like_user_id,
            'reply_like_user_name' => $user_name,
            'reply_like_reply_id' => $entry->reply_like_reply_id
        );

        // Find the reply to which this like belongs and increment its like count
        foreach ($timeline_entries[$entry->id]['replies'] as &$reply) {
            if ($reply['reply_id'] == $entry->reply_like_reply_id) {
                $reply['reply_likes_count']++;
                break;
            }
        }
    }
}

// Convert associative arrays to indexed arrays
foreach ($timeline_entries as &$timeline_entry) {
    $timeline_entry['likes'] = array_values($timeline_entry['likes']);
    $timeline_entry['replies'] = array_values($timeline_entry['replies']);
    $timeline_entry['reply_likes'] = array_values($timeline_entry['reply_likes']);
}
$indexed_timeline_entries = array_values($timeline_entries);
    $taxonomies = get_post_taxonomies($post);
    // var_dump($taxonomies);
    // die;

    // Initialize array to store taxonomy data
    $taxonomy_data = array();

    foreach ($taxonomies as $taxonomy) {
    // Get terms for each taxonomy
    $terms = get_the_terms($post_id, $taxonomy);

    if ($terms && !is_wp_error($terms)) {
        if ($taxonomy === 'city') {
            // Handle 'city' taxonomy with parent-child structure
            $city_data = array();

            foreach ($terms as $term) {
                if ($term->parent == 0) {
                    // This is a parent term (e.g., continent)
                    $continent_data = array(
                        'id' => $term->term_id,
                        'name' => $term->name,
                        'slug' => $term->slug,
                        'children' => array(),
                    );

                    // Find and add children (e.g., cities) to this parent
                    foreach ($terms as $child_term) {
                        if ($child_term->parent == $term->term_id) {
                            $city_data = array(
                                'id' => $child_term->term_id,
                                'name' => $child_term->name,
                                'slug' => $child_term->slug,
                            );
                            $continent_data['children'][] = $city_data;
                        }
                    }

                    $taxonomy_data[$taxonomy][] = $continent_data;
                }
            }
        } else {
            // Handle other taxonomies as usual
            $taxonomy_data[$taxonomy] = array();

            foreach ($terms as $term) {
                // Get term data
                $term_data = array(
                    'id' => $term->term_id,
                    'name' => $term->name,
                    'slug' => $term->slug,
                    // 'description' => $term->description,
                );

                $taxonomy_data[$taxonomy][] = $term_data;
            }
        }
    }
}
    // Convert the associative array into a simple indexed array
    $timeline_entries = array_values($timeline_entries);
    $query = $wpdb->prepare("
        SELECT *
        FROM {$wpdb->prefix}voxel_relations
        WHERE child_id = %d
    ", $post_id);

    $related_parent_ids = $wpdb->get_results($query, ARRAY_A);

    $related_posts = array();
    foreach ($related_parent_ids as $related_parent_id) {
      $parent_post = get_post($related_parent_id['parent_id']);

      if ($parent_post && $parent_post->post_status === 'publish') {
        $profile_logo_image_url = '';
        $profile_image_id = get_post_meta($parent_post->ID, 'logo', true);
        if ($profile_image_id) {
          $profile_logo_image_url = wp_get_attachment_url($profile_image_id);
        }

        $related_posts[] = array(
          'id' => $parent_post->ID,
          'title' => $parent_post->post_title,
          //'content' => $parent_post->post_content,
          'profile_logo_image_url' => $profile_logo_image_url,
          'realtion_key' => $related_parent_id['relation_key'],
          // Add more fields as needed
        );
      }
    }

    $data = array(
      'id' => $post->ID,
      'title' => $post->post_title,
      'content' => $post->post_content,
      'featured_image_url' => $featured_image_url,
      'profile_image_url' => $profile_image_url,
      'gallery_images' => $gallery_images,
      'isVerified'=> $voxel_verified,
      'review_post'=> $categories_review,
      'meta_data' => $meta_data,
      'social_link'=> $formatted_data_socail,
      'timeline_entries' => array_values($timeline_entries),
      'taxonomy_data' => $taxonomy_data,
      'Posted by' => $related_posts,
      'share'=>get_permalink($post->ID)
    );

    return rest_ensure_response($data);
  }
  function hasLike($likes, $user_id)
  {
    foreach ($likes as $like) {
      if ($like['like_user_id'] == $user_id) {
        return true;
      }
    }
    return false;
  }
  function hasLikea($likes, $user_id)
  {
    foreach ($likes as $like) {
      if ($like['reply_like_user_id'] == $user_id) {
        return true;
      }
    }
    return false;
  }
}
$postget = new postget();
//for event api by id
class postgete
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'postgete'));
  }
  function postgete()
  {
    register_rest_route(
      'Voxel/v1',
      '/postgete/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $post_id = $request->get_param('id');
    $post = get_post($post_id);

    if (!$post || $post->post_status !== 'publish') {
      return new \WP_Error('invalid_post_id', 'Invalid post ID', array('status' => 404));
    }

    $featured_image_url = '';
    $featured_image_id = get_post_thumbnail_id($post->ID);
    if ($featured_image_id) {
      $featured_image_url = wp_get_attachment_url($featured_image_id);
    }

    $profile_image_url = '';
    $profile_image_id = get_post_meta($post->ID, 'logo', true);
    if ($profile_image_id) {
      $profile_image_url = wp_get_attachment_url($profile_image_id);
    }
    // var_dump($profile_image_url);
    // die;
    $gallery_images = array();
    $gallery_ids = get_post_meta($post->ID, 'gallery', true);

    if ($gallery_ids) {
      $gallery_ids_array = explode(',', $gallery_ids);
      foreach ($gallery_ids_array as $gallery_id) {
        $gallery_image_url = wp_get_attachment_url($gallery_id);
        if ($gallery_image_url) {
          $gallery_images[] = $gallery_image_url;
        }
      }
    }
    $meta_data = array();
    $meta_data = get_post_meta($post->ID);
    $voxel_verified = isset($meta_data['voxel:verified'][0]) && $meta_data['voxel:verified'][0] == '1' ? true : false;
    $meta_data_json = get_post_meta($post_id, 'voxel:review_stats', true);
    $meta_review_array = json_decode($meta_data_json, true);
    $categories_review = array(
    'total' => isset($meta_review_array['total']) ? $meta_review_array['total'] + 3 : '',
    'average' => isset($meta_review_array['average']) ? $meta_review_array['average'] + 3 : '',
    'total_people' => isset($meta_review_array['by_score']) ? $meta_review_array['by_score'] : '',
    'overall' => isset($meta_review_array['by_category']['score']) ? $meta_review_array['by_category']['score'] + 3 : '',
    'service' => isset($meta_review_array['by_category']['custom-660']) ? $meta_review_array['by_category']['custom-660'] + 3 : '',
    'hospitality' => isset($meta_review_array['by_category']['custom-978']) ? $meta_review_array['by_category']['custom-978'] + 3 : '',
    'pricing' => isset($meta_review_array['by_category']['custom-271']) ? $meta_review_array['by_category']['custom-271'] + 3 : '',
    );
    
    // Decode the  JSON string to a PHP array
    foreach ($meta_data as $key => $value) {
      $meta_data[$key] = maybe_unserialize($value[0]);
    }

    $repeater= array();
    $repeater= get_post_meta($post->ID);
    foreach ($repeater as $key => $value) {
      $repeater[$key] = maybe_unserialize(json_decode($value[0]));
    }
    $repeater_data= array();
    if (isset($repeater['repeater-2']) && is_array($repeater['repeater-2'])) {
      foreach ($repeater['repeater-2'] as $item) {
        if (isset($item->taxonomy, $item->url)) {
          $repeater_data[] = array(
            'url' => $item->url
          );
        }
      }
    }
    global $wpdb;
    $query = "
    SELECT 
        t.*,
        r.id AS reply_id,
        r.user_id AS reply_user_id,
        r.content AS reply_content,
        r.details AS reply_details,
        r.created_at AS reply_created_at,
        r.edited_at AS reply_edited_at,
        l.user_id AS like_user_id,
        l.status_id AS like_status_id,
        rl.user_id AS reply_like_user_id,
        rl.reply_id AS reply_like_reply_id
    FROM
        {$wpdb->prefix}voxel_timeline t
    LEFT JOIN {$wpdb->prefix}voxel_timeline_replies r ON t.id = r.status_id
    LEFT JOIN wp_voxel_timeline_likes l ON t.id = l.status_id
    LEFT JOIN wp_voxel_timeline_reply_likes rl ON r.id = rl.reply_id
    WHERE
        t.post_id = %d
    ORDER BY
        t.created_at ASC, r.created_at ASC
";

    $timeline_data = $wpdb->get_results($wpdb->prepare($query, $post_id));
    // print_r($timeline_data);
    // die;
    $timeline_entries = array();
    foreach ($timeline_data as $entry) {
      // If it's a new timeline entry, create a new entry in the timeline_entries array
      if (!isset($timeline_entries[$entry->id])) {
        $user_info = get_userdata($entry->user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id] = array(
          'id' => $entry->id,
          'user_id' => $entry->user_id,
          'user_name' => $user_name,
          'published_as' => $entry->published_as,
          'post_id' => $entry->post_id,
          'content' => $entry->content,
          'details' => $entry->details,
          'review_score' => $entry->review_score,
          'created_at' => $entry->created_at,
          'edited_at' => $entry->edited_at,
          'replies' => array(),
          'likes' => array(),
          'reply_likes' => array() // Initialize the likes array
        );
      }

      // If there is a like for this timeline entry, add it to the likes array
      if ($entry->like_user_id && !$this->hasLike($timeline_entries[$entry->id]['likes'], $entry->like_user_id)) {
        $user_info = get_userdata($entry->like_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['likes'][] = array(
          'like_user_id' => $entry->like_user_id,
          'like_user_name'=>$user_name,
          'like_status_id' => $entry->like_status_id
        );
      }

      // If there is a reply for this timeline entry, add it to the replies array
      if ($entry->reply_id) {
        $user_info = get_userdata($entry->reply_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['replies'][] = array(
          'reply_id' => $entry->reply_id,
          'reply_user_id' => $entry->reply_user_id,
          'reply_user_name' =>$user_name,
          'reply_content' => $entry->reply_content,
          'reply_details' => $entry->reply_details,
          'reply_created_at' => $entry->reply_created_at,
          'reply_edited_at' => $entry->reply_edited_at
        );
      }
      if ($entry->reply_like_user_id && !$this->hasLikea($timeline_entries[$entry->id]['reply_likes'], $entry->reply_like_user_id)) {
        $user_info = get_userdata($entry->reply_like_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['reply_likes'][] = array(
          'reply_like_user_id' => $entry->reply_like_user_id,
          'reply_like_user_name' =>$user_name,
          'reply_like_reply_id' => $entry->reply_like_reply_id
        );
      }
    }
    $taxonomies = get_post_taxonomies($post);
    // var_dump($taxonomies);
    // die;

    // Initialize array to store taxonomy data
    $taxonomy_data = array();

    foreach ($taxonomies as $taxonomy) {
      // Get terms for each taxonomy
      $terms = get_the_terms($post_id, $taxonomy);

      if ($terms && !is_wp_error($terms)) {
        $taxonomy_data[$taxonomy] = array();

        foreach ($terms as $term) {
          // Get term data
          $term_data = array(
            'id' => $term->term_id,
            'name' => $term->name,
            'slug' => $term->slug,
            // 'description' => $term->description,
          );

          $taxonomy_data[$taxonomy][] = $term_data;
        }
      }
    }
    // Convert the associative array into a simple indexed array
    $timeline_entries = array_values($timeline_entries);
   $query = $wpdb->prepare("
    SELECT *
    FROM {$wpdb->prefix}voxel_relations
    WHERE child_id = %d
    AND relation_key = 'event-place'
    ", $post_id);

    $related_parent_ids = $wpdb->get_results($query, ARRAY_A);

    $related_posts = array();
    foreach ($related_parent_ids as $related_parent_id) {
      $parent_post = get_post($related_parent_id['parent_id']);

      if ($parent_post && $parent_post->post_status === 'publish') {
        $profile_logo_image_url = '';
        $profile_image_id = get_post_meta($parent_post->ID, 'logo', true);
        if ($profile_image_id) {
          $profile_logo_image_url = wp_get_attachment_url($profile_image_id);
        }

        $related_posts = array(
          'id' => $parent_post->ID,
          'title' => $parent_post->post_title,
          //'content' => $parent_post->post_content,
          'profile_logo_image_url' => $profile_logo_image_url,
          'realtion_key' => $related_parent_id['relation_key'],
          // Add more fields as needed
        );
      }
    }
    
    $data = array(
      'id' => $post->ID,
      'title' => $post->post_title,
      'content' => $post->post_content,
      'featured_image_url' => $featured_image_url,
      'profile_image_url' => $profile_image_url,
      'gallery_images' => $gallery_images,
      
      'meta_data' => $meta_data,
      'social_link'=> $repeater_data,
      'timeline_entries' => $timeline_entries,
      'taxonomy_data' => $taxonomy_data,
      'hosted_by' => $related_posts,
      'share' =>get_permalink($post->ID),
    );

    return rest_ensure_response($data);
  }
  function hasLike($likes, $user_id)
  {
    foreach ($likes as $like) {
      if ($like['like_user_id'] == $user_id) {
        return true;
      }
    }
    return false;
  }
  function hasLikea($likes, $user_id)
  {
    foreach ($likes as $like) {
      if ($like['reply_like_user_id'] == $user_id) {
        return true;
      }
    }
    return false;
  }
}
$postgete = new postgete();

class allevent
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'allevent'));
  }
  function allevent()
  {
    register_rest_route(
      'Voxel/v1',
      '/allevent',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $per_page = $request->get_param('per_page') ? intval($request->get_param('per_page')) : 5;
    $page = $request->get_param('page') ? intval($request->get_param('page')) : 1;

    $offset = ($page - 1) * $per_page;
    $total_posts = wp_count_posts('events')->publish;

    // Calculate total pages
    $total_pages = ceil($total_posts / $per_page);
    // If the requested page is beyond the total pages, return an empty array
    if ($page > $total_pages) {
      return array(
        'formatted_posts' => [],
        'total_pages' => $total_pages
      );
    }
    $events = get_posts(array(
      'post_type' => 'events',
      'post_status' => 'publish',
      'posts_per_page' => $per_page, // Get all posts//-1(for all)
      'offset'=> $offset,
    ));
    if (empty($events)) {
      return new \WP_Error('no_events_found', 'No events found.', array('status' => 404));
    }
    $formatted_posts = array();

    foreach ($events  as $events) {
      $featured_image_id = get_post_thumbnail_id($events->ID);
      $featured_image_url = '';
      if ($featured_image_id) {
        $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
        if (is_array($featured_image_data)) {
          $featured_image_url = $featured_image_data[0];
        }
      }
      $event_date = get_post_meta($events->ID, 'event_date', true);
      $profile_logo_id = get_post_meta($events->ID, 'logo', true);
      $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';
      $address = get_post_meta($events->ID, 'location', true);
      $address_data = json_decode($address, true);
      // Extract the desired components
      $address = isset($address_data['address']) ? $address_data['address'] : '';
      $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
      $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';
      $formatted_posts[] = array(
        'id' => $events->ID,
        'name' => $events->post_title,
        'content' => $events->post_content,
        'featured_image_url' => $featured_image_url,
        'profile_logo_url' => $profile_logo_url,
        'address' => $address,
        'latitude' => $latitude,
        'longitude' => $longitude,
        'event_date' => $event_date,
      );
    }
  return array(
        'formatted_posts' => $formatted_posts,
        'total_pages' => $total_pages
    );
  }
}
$allevent = new allevent();

class allcatp
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'allcatp'));
  }
  function allcatp()
  {
    register_rest_route(
      'Voxel/v1',
      '/allcatp',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $taxonomy = 'places_category';
    $categories = get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false, // Set to false to include empty terms
    ));

    if (is_wp_error($categories)) {
      return $categories;
    }

    if (empty($categories)) {
      return new \WP_Error('no_categories_found', 'No categories found.', array('status' => 404));
    }

    $formatted_categories = array();
    foreach ($categories as $category) {
      // // $termid= $category['id'];
      // // $termname= $category['label'];
      // // $termslug= $category['slug'];
      $formatted_categories[] = array(
        'id' =>  $category['id'],
        'name' => $category['label'],
        'slug' => $category['slug'],
        'icon' => $category['icon'],
        //'icon'=> $categories['icon'],
        // Add more fields as needed
      );
    }

    return $formatted_categories;
  }
}
$allcatp = new allcatp();

class pricerange
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'pricerange'));
  }
  function pricerange()
  {
    register_rest_route(
      'Voxel/v1',
      '/pricerange',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'price'),
      )
    );
  }

  function price()
  {
    $taxonomy = 'price_range';
    $pricerange = get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false, // Set to false to include empty terms
    ));
    if (is_wp_error($pricerange)) {
      return  $pricerange;
    }

    if (empty($pricerange)) {
      return new \WP_Error('no_pricerange_found', 'No pricerange found.', array('status' => 404));
    }
    $formatted_pricerange = array();
    foreach ($pricerange as $price) {
      $formatted_pricerange[] = array(
        'id' =>  $price['id'],
        'name' => $price['label'],
        'slug' => $price['slug'],

      );
    }
    return  $formatted_pricerange;
  }
}
$pricerange = new pricerange();

class social
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'social'));
  }
  function social()
  {
    register_rest_route(
      'Voxel/v1',
      '/social',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }

  function getall()
  {
    $taxonomy = 'places_social_networks';

    $social = get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false, // Set to false to include empty terms
    ));
    if (is_wp_error($social)) {
      return  $social;
    }

    if (empty($social)) {
      return new \WP_Error('no_social_found', 'No social found.', array('status' => 404));
    }
    $formatted_social = array();
    foreach ($social as $social1) {
      $formatted_social[] = array(
        'id' =>  $social1['id'],
        'name' => $social1['label'],
        'slug' => $social1['slug'],

      );
    }
    return  $formatted_social;
  }
}
$social = new social();

class Category_API
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    function register_routes()
    {
        register_rest_route(
            'Voxel/v1',
            '/blogcategories',
            array(
                'methods' => 'GET',
                'callback' => array($this, 'get_all_categories'),
            )
        );
    }

    function get_all_categories()
    {
        $taxonomy = 'category'; // Use 'category' taxonomy for categories

        $categories = get_terms(array(
            'taxonomy' => $taxonomy,
            'hide_empty' => false, // Set to false to include empty categories
        ));

        if (is_wp_error($categories)) {
            return $categories;
        }

        if (empty($categories)) {
            return new \WP_Error('no_categories_found', 'No categories found.', array('status' => 404));
        }

        $formatted_categories = array();
        foreach ($categories as $category) {
            $formatted_categories[] = array(
                'id' => $category['id'], // Use term_id for category ID
                'name' => $category['label'], // Use name for category name
                'slug' => $category['slug'], // Use slug for category slug
            );
        }

        return $formatted_categories;
    }
}

$category_api = new Category_API();


class getcities
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'getcities'));
  }
  function getcities()
  {
    register_rest_route(
      'Voxel/v1',
      '/getcities',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $taxonomy = 'city';
    $city = get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false,
      'hierarchical' => true,
    ));
    if (is_wp_error($city)) {
      return  $city;
    }
    if (empty($city)) {
      return new \WP_Error('no_cities_found', 'No cities found.', array('status' => 404));
    }
    
    $formatted_city = array();

    foreach ($city as $continent) {
      $continent_data = array(
        'id' => $continent['id'],
        'parent' => $continent['parent'],
        'slug' => $continent['slug'],
        'name' => $continent['label'],
        'children' => array(),
      );

            // Check if the continent has children cities
      if (!empty($continent['children'])) {
        foreach ($continent['children'] as $city2) {
          $city2_data = array(
            'id' => $city2['id'],
            'parent' => $city2['parent'],
            'slug' => $city2['slug'],
            'name' => $city2['label'],
          );
          $continent_data['children'][] = $city2_data;
        }
      }

      $formatted_city[] = $continent_data;
    }

    return $formatted_city;
  }
}
$getcities = new getcities();

class getamenities
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'getamenities'));
  }
  function getamenities()
  {
    register_rest_route(
      'Voxel/v1',
      '/getamenities',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
 
    function getall()
    {
        $taxonomy = 'amenities';
        $amenities = get_terms(array(
            'taxonomy' => $taxonomy,
            'hide_empty' => false,
            'hierarchical' => true,
        ));

        if (is_wp_error($amenities)) {
            return $amenities;
        }

        if (empty($amenities)) {
            return new \WP_Error('no_amenities_found', 'No amenities found.', array('status' => 404));
        }

        $formatted_amenities = $this->format_amenities($amenities);

        return $formatted_amenities;
    }

    private function format_amenities($amenities)
    {
        $result = array();

        foreach ($amenities as $amenity) {
            $amenity_data = array(
                'id' => $amenity['id'],
                'parent' => $amenity['parent'],
                'slug' => $amenity['slug'],
                'label' => $amenity['label'],
                'order' => $amenity['order'],
                'icon' => $amenity['icon'],
                'children' => array(),
            );

            if (!empty($amenity['children'])) {
                foreach ($amenity['children'] as $child) {
                    $child_data = array(
                        'id' => $child['id'],
                        'parent' => $child['parent'],
                        'slug' => $child['slug'],
                        'label' => $child['label'],
                        'order' => $child['order'],
                        'icon' => $child['icon'],
                        'children' => array(),
                    );

                    $amenity_data['children'][] = $child_data;
                }
            }

            $result[] = $amenity_data;
        }

        return $result;
    }
}
$getamenities = new getamenities();

class rastag
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'rastag'));
  }
  function rastag()
  {
    register_rest_route(
      'Voxel/v1',
      '/rastag',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $taxonomy = 'restaurant-tags';
    $rastag = get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false,
    ));
    if (is_wp_error($rastag)) {
      return  $rastag;
    }

    if (empty($rastag)) {
      return new \WP_Error('no_restaurant_tags_found', 'No restaurant tags found.', array('status' => 404));
    }
    $formatted_rastag = array();
    foreach ($rastag as $ras) {
      $formatted_rastag[] = array(
        'id' => $ras['id'],
        'name' => $ras['label'],
        'slug' => $ras['slug'],

      );
    }
    return $formatted_rastag;
  }
}
$rastag = new rastag();
class events_category
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'events_category'));
  }
  function events_category()
  {
    register_rest_route(
      'Voxel/v1',
      '/events_category',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $taxonomy = 'events-category';
    $events_category = get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false,
    ));
    if (is_wp_error($events_category)) {
      return  $events_category;
    }

    if (empty($events_category)) {
      return new \WP_Error('no_events_category_found', 'No events category found.', array('status' => 404));
    }
    $formatted_events_category= array();
    foreach ($events_category as $category) {
      $formatted_events_category[] = array(
        'id' => $category['id'],
        'name' => $category['label'],
        'slug' => $category['slug'],

      );
    }
    return $formatted_events_category;
  }
}
$events_category = new events_category();

class events_price
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'events_price'));
  }
  function events_price()
  {
    register_rest_route(
      'Voxel/v1',
      '/events_price',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $taxonomy = 'event-pricing';
    $events_price= get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false,
    ));
    if (is_wp_error($events_price)) {
      return  $events_price;
    }

    if (empty($events_price)) {
      return new \WP_Error('no_events_price_found', 'No events price found.', array('status' => 404));
    }
    $formatted_events_price= array();
    foreach ($events_price as $category) {
      $formatted_events_price[] = array(
        'id' => $category['id'],
        'name' => $category['label'],
        'slug' => $category['slug'],

      );
    }
    return $formatted_events_price;
  }
}
$events_price = new events_price();
class jobs_industry{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'jobs_industry'));
  }
  function jobs_industry()
  {
    register_rest_route(
      'Voxel/v1',
      '/jobs_industry',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $taxonomy = 'jobs_industry';
    $jobs_industry= get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false,
    ));
    if (is_wp_error($jobs_industry)) {
      return  $jobs_industry;
    }

    if (empty($jobs_industry)) {
      return new \WP_Error('no_jobs_found', 'No jobs industry found.', array('status' => 404));
    }
    $formatted_jobs_industry= array();
    foreach ($jobs_industry as $category) {
      $formatted_jobs_industry[] = array(
        'id' => $category['id'],
        'name' => $category['label'],
        'slug' => $category['slug'],

      );
    }
    return $formatted_jobs_industry;
  }
}
$jobs_industry = new jobs_industry();

class job_type{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'job_type'));
  }
  function job_type()
  {
    register_rest_route(
      'Voxel/v1',
      '/job_type',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $taxonomy = 'jobs_job_type';
    $job_type= get_terms(array(
      'taxonomy' => $taxonomy,
      'hide_empty' => false,
    ));
    if (is_wp_error($job_type)) {
      return  $job_type;
    }

    if (empty($job_type)) {
      return new \WP_Error('no_jobs_found', 'No jobs industry found.', array('status' => 404));
    }
    $formatted_job_type= array();
    foreach ($job_type as $category) {
      $formatted_job_type[] = array(
        'id' => $category['id'],
        'name' => $category['label'],
        'slug' => $category['slug'],

      );
    }
    return $formatted_job_type;
  }
}
$job_type = new job_type();

class catplace
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'catplace'));
  }
  function catplace()
  {
    register_rest_route(
      'Voxel/v1',
      '/catplace/(?P<category_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $category_id = $request->get_param('category_id');

    $args = array(
      'post_type' => 'places', // Change 'places' to your actual post type
      'posts_per_page' => -1, // Retrieve all posts
      'tax_query' => array(
        array(
          'taxonomy' => 'places_category', // Change 'places_category' to your actual taxonomy
          'field' => 'term_id',
          'terms' => $category_id,
        ),
      ),
    );
    $posts = get_posts($args);

    if (empty($posts)) {
      return new WP_Error('no_posts_found', 'No posts found in the specified category.', array('status' => 404));
    }
    $formatted_posts = array();
    foreach ($posts as $post) {
      $formatted_posts[] = array(
        'ID' => $post->ID,
        'post_author' => $post->post_author,
        'post_date' => $post->post_date,
        'post_date_gmt' => $post->post_date_gmt,
        'post_content' => $post->post_content,
        'post_title' => $post->post_title,
      );
    }
    return  $formatted_posts;
  }
}
$catplace = new catplace();

// class postget{
//   function __construct()
//   {
//     add_action( 'rest_api_init', array( $this, 'postget') );
//   }
//   function postget(){
//     register_rest_route(
//       'Voxel/v1',
//       '/postget/(?P<id>\d+)',
//       array(
//         'methods' => 'GET',
//         'callback' => array($this, 'getpost'),
//       )
//     );
//   }
//   function getpost($request) {
//     $place_id = $request->get_param('id');

//     // Get place data
//     $place = get_post($place_id);

//     if (!$place) {
//         return new WP_Error('place_not_found', 'Place not found.', array('status' => 404));
//     }

//     // Get featured image
//     $featured_image_id = get_post_thumbnail_id($place_id);
//     $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');

//     // Get all inherited image data
//     $inherited_images = array();
//     $ancestors = get_post_ancestors($place_id);
//     foreach ($ancestors as $ancestor) {
//         $ancestor_featured_image_id = get_post_thumbnail_id($ancestor);
//         $ancestor_featured_image_data = wp_get_attachment_image_src($ancestor_featured_image_id, 'full');
//         $inherited_images[] = array(
//             'id' => $ancestor_featured_image_id,
//             'url' => $ancestor_featured_image_data[0],
//             'width' => $ancestor_featured_image_data[1],
//             'height' => $ancestor_featured_image_data[2],
//         );
//     }

//     $response = array(
//         'id' => $place_id,
//         'title' => $place->post_title,
//         'content' => $place->post_content,
//         'featured_image' => array(
//             'id' => $featured_image_id,
//             'url' => $featured_image_data[0],
//             'width' => $featured_image_data[1],
//             'height' => $featured_image_data[2],
//         ),
//         'inherited_images' => $inherited_images,
//     );

//     return rest_ensure_response($response);
// }
// }
// $postget = new postget();

class category
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'allcat'));
  }
  function allcat()
  {
    register_rest_route(
      'Voxel/v1',
      '/allcat',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall()
  {
    $formatted_categories = array();

    foreach ($categories as $category) {
      $posts_in_category = get_posts(array(
        'category' => $category->term_id,
        'posts_per_page' => -1, // Get all posts in the category
      ));

      $formatted_posts = array();

      foreach ($posts_in_category as $post) {
        $formatted_posts[] = array(
          'id' => $post->ID,
          'title' => $post->post_title,
          'content' => $post->post_content,
          // Add more fields as needed
        );
      }

      $formatted_categories[] = array(
        'id' => $category->term_id,
        'name' => $category->name,
        'slug' => $category->slug,
        'posts' => $formatted_posts,
      );
    }

    return $formatted_categories;
  }
}
$category = new category();

class profileg
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'profileg'));
  }

  function profileg()
  {
    register_rest_route(
      'Voxel/v1',
      '/profileg/(?P<user_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }

  public function getall($request)
  {
    $user_id = $request->get_param('user_id'); // Get the user ID from the request

    $listings = $this->get_listings_for_user($user_id);

    return rest_ensure_response($listings);
  }

  function get_listings_for_user($user_id)
  {
    global $wpdb;
    // $args = array(
    //     'post_type' => 'places',
    //     'post_author'=> $user_id,
    //      'posts_per_page' => -1,
    // );
    // $listings_query = new \WP_Query($args);
    // var_dump($listings_query->request);
    // die;
    $query = "SELECT *
                FROM wp_posts
                WHERE 1=1
                    AND wp_posts.post_type = 'places'
                    AND wp_posts.post_author = $user_id
                    AND wp_posts.post_status = 'publish'
                ORDER BY wp_posts.post_date DESC";
    $results = $wpdb->get_results($query);
    $listings = array();
    foreach ($results as $result) {
      $featured_image_id = get_post_thumbnail_id($result->ID);
      if ($featured_image_id) {
        $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
        if (is_array($featured_image_data)) {
          $result->featured_image_url = $featured_image_data[0];
        }
      }
      $profile_logo = get_post_meta($result->ID, 'logo', true);
      if ($profile_logo) {
        $result->profile_logo_url = wp_get_attachment_url($profile_logo);
      }
      $listings[] = $result;
    }
    return $listings;
  }
}

$profileg = new profileg();

class profilej
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'profilej'));
  }
  function profilej()
  {
    register_rest_route(
      'Voxel/v1',
      '/profilej/(?P<user_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $user_id = $request->get_param('user_id'); // Get the user ID from the request

    $listings = $this->get_listings_for_user($user_id);

    return rest_ensure_response($listings);
  }
  function get_listings_for_user($user_id)
  {
    global $wpdb;
    // $args = array(
    //     'post_type' => 'places',
    //     'post_author'=> $user_id,
    //      'posts_per_page' => -1,
    // );
    // $listings_query = new \WP_Query($args);
    // var_dump($listings_query->request);
    // die;
    $query = "SELECT *
                  FROM wp_posts
                  WHERE 1=1
                      AND wp_posts.post_type = 'jobs'
                      AND wp_posts.post_author = $user_id
                      AND wp_posts.post_status = 'publish'
                  ORDER BY wp_posts.post_date DESC";
    $results = $wpdb->get_results($query);
    //   $listings = array();
    //   foreach ($results as $result) {
    //     $featured_image_id = get_post_thumbnail_id($result->ID);
    //     if ($featured_image_id) {
    //         $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
    //         if (is_array($featured_image_data)) {
    //             $result->featured_image_url = $featured_image_data[0];
    //         }
    //     }
    //     $profile_logo = get_post_meta($result->ID, 'logo', true);
    //     if ($profile_logo) {
    //         $result->profile_logo_url = wp_get_attachment_url($profile_logo);
    //     }
    //     $listings[] = $result;
    // }
    $formatted_results = array();
    if ($results) {
      foreach ($results as $result) {
        $profile_logo_id = get_post_meta($result->ID, 'logo', true);
        $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';

        $formatted_results[] = array(
          'id' => $result->ID,
          'title' => $result->post_title,
          //'content' => $result->post_content,
          'logo' => $profile_logo_url,
          'name' => $result->post_name,
          // Add more fields as needed
        );
      }
    }
    return $formatted_results;
  }
}
$profilej = new profilej();

class profilee
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'profilee'));
  }
  function profilee()
  {
    register_rest_route(
      'Voxel/v1',
      '/profilee/(?P<user_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $user_id = $request->get_param('user_id'); // Get the user ID from the request

    $listings = $this->get_listings_for_user($user_id);

    return rest_ensure_response($listings);
  }
  function get_listings_for_user($user_id)
  {
    global $wpdb;
    // $args = array(
    //     'post_type' => 'places',
    //     'post_author'=> $user_id,
    //      'posts_per_page' => -1,
    // );
    // $listings_query = new \WP_Query($args);
    // var_dump($listings_query->request);
    // die;
    $query = "SELECT *
                  FROM wp_posts
                  WHERE 1=1
                      AND wp_posts.post_type = 'events'
                      AND wp_posts.post_author = $user_id
                      AND wp_posts.post_status = 'publish'
                  ORDER BY wp_posts.post_date DESC";
    $results = $wpdb->get_results($query);
    $formatted_results = array();
    if ($results) {
      foreach ($results as $result) {
        $profile_logo_id = get_post_meta($result->ID, 'logo', true);
        $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';

        $formatted_results[] = array(
          'id' => $result->ID,
          'title' => $result->post_title,
          'content' => $result->post_content,
          'logo' => $profile_logo_url,
          // Add more fields as needed
        );
      }
    }

    //   foreach ($results as $result) {
    //     $listing = array();
    //     $listing['title'] = $result->post_title;
    //     $featured_image_id = get_post_thumbnail_id($result->ID);
    //     if ($featured_image_id) {
    //         $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
    //         if (is_array($featured_image_data)) {
    //             $result->featured_image_url = $featured_image_data[0];
    //         }
    //     }
    //     $profile_logo = get_post_meta($result->ID, 'logo', true);
    //     if ($profile_logo) {
    //         $result->profile_logo_url = wp_get_attachment_url($profile_logo);
    //     }
    //     $listings[] = $listing;
    // }
    return $formatted_results;
  }
}

$profilee = new profilee();

class postst
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'postst'));
  }
  function postst()
  {
    register_rest_route(
      'Voxel/v1',
      '/postst/(?P<id>\d+)',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'changes'),
      )
    );
  }

  function changes($request)
  {
    $id = $request->get_param('id');
    $post = get_post($id);
    if (!$post) {
      return new \WP_Error('post_not_found', 'Post not found', array('status' => 404));
    }
    $new_status = $post->post_status === 'publish' ? 'unpublished' : 'publish';

    $updated_post = wp_update_post(array(
      'ID' => $id,
      'post_status' => $new_status,
    ), true);

    if (is_wp_error($updated_post)) {
      return new \WP_Error('post_update_error', 'Error updating post', array('status' => 500));
    }

    return rest_ensure_response(array('message' => 'Post status updated', 'new_status' => $new_status));
  }
}
$postst = new postst();

class deletp
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'deletp'));
  }
  function deletp()
  {
    register_rest_route(
      'Voxel/v1',
      '/deletp/(?P<id>\d+)',
      array(
        'methods' => 'DELETE',
        'callback' => array($this, 'delete'),
      )
    );
  }
  function delete($request)
  {
    $id = $request->get_param('id');

    $result = wp_delete_post($id, true);
    if ($result === false) {
      return new \WP_Error('failed', 'Failed to delete the post.', array('status' => 500));
    }
    return array('message' => 'Post deleted successfully.');
  }
}
$deletp = new deletp();

class search
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'search'));
  }
  function search()
  {
    register_rest_route(
      'Voxel/v1',
      '/searchp-place',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'searchp'),
      )
    );
    // register_rest_route(
    //   'Voxel/v1',
    //   '/search', // No query parameter
    //   array(
    //     'methods' => 'GET',
    //     'callback' => array($this, 'handle_empty_search'),
    //   )
    // );
  }

  function handle_empty_search()
  {
    if (empty($search_query)) {
      return new \WP_Error('invalid_search', 'Search query cannot be empty.', array('status' => 400));
    }
  }

  function searchp($request)
  {
     $search_query = $request->get_param('query');
    $per_page = $request->get_param('per_page') ? intval($request->get_param('per_page')) : 5;
    $page = $request->get_param('page') ? intval($request->get_param('page')) : 1;


    if (empty($search_query)) {
      return new \WP_Error('invalid_search', 'Search query cannot be empty.', array('status' => 400));
    }

    // Perform your search logic here
    $search_results = $this->custom_search_function($search_query, $per_page, $page);


    // Return the search results
    return rest_ensure_response($search_results);
  }

  function custom_search_function($search_query, $per_page, $page)
  {
    global $wpdb;
    $table_name = $wpdb->prefix . 'posts'; // Get the table name with prefix
    
    $offset = ($page - 1) * $per_page;
    // Prepare SQL query
    $sql = $wpdb->prepare("
        SELECT ID, post_title, post_content
        FROM $table_name
        WHERE 1=1
            AND (post_title LIKE %s
            OR post_excerpt LIKE %s
            OR post_content LIKE %s)
            AND post_status = 'publish'
            AND post_type = 'places'
        ORDER BY post_date DESC
         LIMIT %d, %d
    ", '%' . $wpdb->esc_like($search_query) . '%', '%' . $wpdb->esc_like($search_query) . '%', '%' . $wpdb->esc_like($search_query) . '%', $offset, $per_page);

    // Execute query
    $results = $wpdb->get_results($sql);

    // Process results
    $formatted_results = array();
    if ($results) {
      foreach ($results as $post) {
        // Get featured image URL
        $featured_image_id = get_post_thumbnail_id($post->ID);
        $featured_image_url = '';
        if ($featured_image_id) {
          $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
          if (is_array($featured_image_data)) {
            $featured_image_url = $featured_image_data[0];
          }
        }

        // Get profile logo URL
        $profile_logo_id = get_post_meta($post->ID, 'logo', true);
        $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';

            // Get address, latitude, and longitude from 'location' meta field
        $address = get_post_meta($post->ID, 'location', true);
        $address_data = json_decode($address, true);
        $address = isset($address_data['address']) ? $address_data['address'] : '';
        $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
        $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';

        // Get review statistics (total reviews and average rating)
        $review_stats_json = get_post_meta($post->ID, 'voxel:review_stats', true);
        $total_reviews = 0;
        $average_rating = '';
        if ($review_stats_json) {
        $review_stats = json_decode($review_stats_json, true); // Decode the JSON to an associative array
        $total_reviews = $review_stats['total'] ?? 0; // Default to 0 if 'total' is not set
        $average_rating = isset($review_stats['average']) ? round($review_stats['average'] + 3, 2) : ''; // Adjust average rating
        }

       // Get and format opening hours
        $opening_hours_data = get_post_meta($post->ID, 'work-hours', true);
        $opening_hours = json_decode($opening_hours_data, true);
        $formatted_opening_hours = array();
        if (!empty($opening_hours) && is_array($opening_hours)) {
          foreach ($opening_hours as $hours_data) {
            $days = $hours_data['days'] ?? array();
            $status = $hours_data['status'] ?? 'hours';
            $hours = $hours_data['hours'] ?? array();

            foreach ($days as $day) {
              if (!isset($formatted_opening_hours[$day])) {
                $formatted_opening_hours[$day] = array();
              }

              // Handle status for closed or appointment-only days
              if ($status === 'closed') {
                $formatted_opening_hours[$day][] = 'Closed all day';
              } elseif ($status === 'appointments_only') {
                $formatted_opening_hours[$day][] = 'Appointments Only';
              } elseif (!empty($hours)) {
              // Add formatted hours
                foreach ($hours as $hour) {
                  $formatted_opening_hours[$day][] = $hour['from'] . '-' . $hour['to'];
                }
              } else {
              // If no hours are provided, indicate that it's open all day
                $formatted_opening_hours[$day][] = 'Open all day';
              }
            }
          }
        }

        // Add all data to formatted results
        $formatted_results[] = array(
          'id' => $post->ID,
          'name' => $post->post_title,
          'content' => $post->post_content,
          'featured_image_url' => $featured_image_url,
          'profile_logo_url' => $profile_logo_url,
          'address' => $address,
          'latitude' => $latitude,
          'longitude' => $longitude,
          'Total Reviews' => $total_reviews,
          'Average Rating' => $average_rating,
          'opening_hours' => $formatted_opening_hours,
        );
      }
    }

    return $formatted_results;
  }
}
$search = new search();

class searchpl
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'searchpl'));
  }

  function searchpl()
  {
    register_rest_route(
      'Voxel/v1',
      '/searchpl',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $params = $request->get_params();
    
    $cities = $this->convertToArray($params['cities'] ?? array());
    $country = $this->convertToArray($params['country'] ?? array());
    $categories = $this->convertToArray($params['categories'] ?? array());
    $amenities = $this->convertToArray($params['amenities'] ?? array());
    // var_dump($amenities);
    // die;
     
    $args = array(
      'post_type' => 'places', // Adjust post type as needed
      'post_status' => 'publish',
      'posts_per_page' => -1, // Retrieve all posts that match the criteria
      'tax_query' => array(
        'relation' => 'AND', // Match all taxonomy criteria
      ),
    );

    if (!empty($cities)) {
      $args['tax_query'][] = array(
        'taxonomy' => 'city',
        'field' => 'term_id',
        'terms' => $cities,
        'include_children' => true,
        'operator' => 'IN',
      );
    }
    if (!empty($country)) {
      $args['tax_query'][] = array(
        'taxonomy' => 'city',
        'field' => 'term_id',
        'terms' => $country,
        'include_children' => true,
        'operator' => 'IN',
      );
    }
    
    if (!empty($categories)) {
      $args['tax_query'][] = array(
        'taxonomy' => 'places_category',
        'field' => 'term_id',
        'terms' => $categories,
        'include_children' => true,
        'operator' => 'IN',
      );
    }

    if (!empty($amenities)) {
      $args['tax_query'][] = array(
          'taxonomy' => 'amenities',
          'field' => 'term_id',
          'terms' => $amenities,
          'include_children' => true,
          'operator' => 'IN',
      );
      
    }

    $query = new \WP_Query($args);
    // Prepare results
    $results = array();
    if ($query->have_posts()) {
      while ($query->have_posts()) {
        $query->the_post();
        $post_data = array(
          'id' => get_the_ID(),
          'name' => get_the_title(),
        );
        $thumbnail_id = get_post_thumbnail_id();
        //$thumbnail = wp_get_attachment_image_src($thumbnail_id, 'thumbnail');
        if ($thumbnail_id) {
          $post_data['featured_image_url'] = wp_get_attachment_url($thumbnail_id);
        }
        $logo_id = get_post_meta(get_the_ID(), 'logo', true);
        if ($logo_id) {
          $logo = wp_get_attachment_image_src($logo_id, 'full');
          if ($logo) {
            $post_data['profile_logo_url'] = $logo[0];
          }
        }
        $text = get_post_meta(get_the_ID(), 'text', true);
        if ($text) {
          $post_data['text'] = $text;
        }
        $address = get_post_meta(get_the_ID(), 'location', true);
        $review_stats_json = get_post_meta(get_the_ID(), 'voxel:review_stats', true);
        if ($review_stats_json) {
        $review_stats = json_decode($review_stats_json, true); // Decode the JSON to an associative array

        $total_reviews = $review_stats['total'] ?? 0; // Using null coalescing operator to provide default value
        $average_rating = isset($review_stats['average'])  ? round($review_stats['average'] + 3, 2) : ''; // Defaulting to '0' if not set
      }
      $post_data['total_reviews']= $total_reviews;
      $post_data['average_rating']= $average_rating;
      // Extract the desired components
      $address_data = json_decode($address, true);
      $address = isset($address_data['address']) ? $address_data['address'] : '';
      $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
      $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';
      $post_data['address']= $address;
      $post_data['latitude']= $latitude;
      $post_data['longitude']= $longitude;

        // Retrieve opening hours
        $hours = get_post_meta(get_the_ID(), 'work-hours', true);
        $opening_hours = json_decode($hours, true);
        if (!empty($opening_hours) && is_array($opening_hours)) {
          $formatted_opening_hours = array();
          foreach ($opening_hours as $hours_data) {
            $days = $hours_data['days'] ?? array();
            $hours = $hours_data['hours'] ?? array();
            foreach ($days as $day) {
              if (!isset($formatted_opening_hours[$day])) {
                $formatted_opening_hours[$day] = array();
              }
              if (!empty($hours)) {
                foreach ($hours as $hour) {
                  $formatted_opening_hours[$day][] = $hour['from'] . '-' . $hour['to'];
                }
              } else {
                $formatted_opening_hours[$day][] = 'Open all day';
              }
            }
          }
          $post_data['opening_hours'] = $formatted_opening_hours;
        }
        $price_range = wp_get_post_terms(get_the_ID(), 'price_range', array('fields' => 'all'));
        if (!is_wp_error($price_range) && !empty($price_range)) {
          $price_range = $price_range[0];
          $post_data['price_name'] = $price_range->name;
          $post_data['price_slug'] = $price_range->slug;
        }
        $results[] = $post_data;
      }
      wp_reset_postdata();
    } else {
      $results[] = array(
        'message' => 'No places found for the given criteria.',
      );
    }

    return rest_ensure_response($results);
  }
  private function convertToArray($input)
  {  
    if (is_string($input)) {
            // Remove quotes and any extra characters, then split by commas or spaces
      $input = trim($input, "[]");
      $input = preg_split('/\s*,\s*/', $input);
            // Clean up each element
      $input = array_map(function ($item) {
                $item = trim($item, '"\''); // Remove quotes
                return intval($item); // Convert to integer
              }, $input);
    }
    return $input;
  }
}

$searchpl = new searchpl();

class searchev
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'searchev'));
  }

  function searchev()
  {
    register_rest_route(
      'Voxel/v1',
      '/searchev',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),

      )
    );
  }
  function getall($request)
  {
    $params = $request->get_json_params();
    $city = $params['city'] ?? array();
    $amenities = $params['amenities'] ?? array();
    $from_date = $params['from_date'] ?? '';
    $to_date = $params['to_date'] ?? '';

    if (count($city) === 1 && strpos($city[0], ',') !== false) {
      $city = explode(',', $city[0]);
    }
    if (count($amenities) === 1 && strpos($amenities[0], ',') !== false) {
      $amenities = explode(',', $amenities[0]);
    }
    $args = array(
      'post_type' => 'events',
      'posts_per_page' => -1, // Retrieve all posts
      'post_status' => 'publish',
      'tax_query' => array(
        'relation' => 'AND', // Match all taxonomy criteria
      ),
      'meta_query' => array(
        'relation' => 'AND',
      ),
    );

    if (!empty($city)) {
      $args['tax_query'][] = array(
        'taxonomy' => 'city',
        'field' => 'slug',
        'terms' => $city,
      );
    }

    $query = new \WP_Query($args);
    $results = array();
    if ($query->have_posts()) {
      while ($query->have_posts()) {
        $query->the_post();
        $event_id = get_the_ID();
        $thumbnail_id = '';
        $thumbnail_id = get_post_thumbnail_id();
        if ($thumbnail_id) {
          $event_data['thumbnail'] = wp_get_attachment_url($thumbnail_id);
        }
        // $thumbnail = wp_get_attachment_image_src($thumbnail_id, 'thumbnail');
        // if ($thumbnail) {
        // $event_data['thumbnail'] = $thumbnail[0];
        // }
        $logo_id = get_post_meta(get_the_ID(), 'logo', true);
        if ($logo_id) {
          $logo = wp_get_attachment_image_src($logo_id, 'full');
          if ($logo) {
            $event_data['logo'] = $logo[0];
          }
        }
        $event_schedule = get_post_meta($event_id, 'event_date', true);
        if (!empty($event_schedule)) {
          $event_schedule = json_decode($event_schedule, true);
          foreach ($event_schedule as $event_occurrence) {
            $start_date = strtotime($event_occurrence['start']);
            $end_date = strtotime($event_occurrence['end']);

            if ($start_date >= strtotime($from_date) || $end_date <= strtotime($to_date)) {
              $event_data = array(
                'id' => $event_id,
                'title' => get_the_title(),
                'start_date' => $event_occurrence['start'],
                'end_date' => $event_occurrence['end'],
                'thumbnail' => $event_data['thumbnail'],
                'logo'     => $event_data['logo']
                // Add more data as needed
              );

              $results[] = $event_data;
            }
          }
        }
      }
      wp_reset_postdata();
    } else {
      $results[] = array(
        'message' => 'No events found for the given criteria.',
      );
    }

    // Return results
    return rest_ensure_response($results);
  }
}
$searchev = new searchev();

class users
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'users'));
  }

  function users()
  {
    register_rest_route(
      'Voxel/v1',
      '/users',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'get'),

      )
    );
  }
  function get($request)
  {
   // Get the name, location, and proximity parameters from the POST request
    $name = sanitize_text_field($request->get_param('name'));
    $location = sanitize_text_field($request->get_param('location'));
    $proximity = sanitize_text_field($request->get_param('proximity')); // Could be distance in km/miles

    // Get users by name
    $users = get_users(array(
      'search'         => '*' . $name . '*',
      'search_columns' => array('user_login', 'user_nicename', 'display_name', 'user_email'),
    ));

    if (empty($users)) {
      return new \WP_Error('user_not_found', 'User not found', array('status' => 404));
    }

    $users_data = array();

    foreach ($users as $user) {
      $profile_pic_url = get_avatar_url($user);

      // Retrieve voxel:profile_id from the user meta
      $profile_id = get_user_meta($user->ID, 'voxel:profile_id', true);

      // If we have a profile ID, get the location meta data
      if ($profile_id) {
        $location_data = get_post_meta($profile_id, 'location', true); // Assuming 'location' meta contains the location data

        // Decode the JSON location data
        $location_meta = json_decode($location_data, true);
        $address = isset($location_meta['address']) ? $location_meta['address'] : '';
        $latitude = isset($location_meta['latitude']) ? $location_meta['latitude'] : '';
        $longitude = isset($location_meta['longitude']) ? $location_meta['longitude'] : '';

        // Handle proximity search if location and proximity are provided
        if (!empty($location) && !empty($proximity)) {
          $user_location = $latitude . ',' . $longitude;

          if ($user_location) {
            // Use a function to calculate distance between user location and the provided location
            $distance = $this->calculate_distance($location, $user_location);

            // Check if the user is within the proximity
            if ($distance > $proximity) {
              continue; // Skip this user if they are outside the proximity
            }
          }
        }

        // Add user data to response
        $users_data[] = array(
          'id' => $user->ID,
          'name' => $user->display_name,
          'profile_pic_url' => $profile_pic_url,
          'profile_id' => $profile_id,
          'address' => $address,
          'latitude' => $latitude,
          'longitude' => $longitude,
        );
      }
    }

    return rest_ensure_response($users_data);
  }
  // Function to calculate the distance between two locations (latitude and longitude)
  function calculate_distance($location1, $location2)
  {
    list($lat1, $lng1) = explode(',', $location1);
    list($lat2, $lng2) = explode(',', $location2);

    $earth_radius = 6371; // Earth's radius in kilometers

    $lat_diff = deg2rad($lat2 - $lat1);
    $lng_diff = deg2rad($lng2 - $lng1);

    $a = sin($lat_diff / 2) * sin($lat_diff / 2) +
      cos(deg2rad($lat1)) * cos(deg2rad($lat2)) *
      sin($lng_diff / 2) * sin($lng_diff / 2);

    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));

    return $earth_radius * $c; // Distance in kilometers
  }
}
$users = new users();

class getblog
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'getblog'));
  }

  function getblog()
  {
    register_rest_route(
      'Voxel/v1',
      '/allgetblog',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get'),

      )
    );
  }
  function get($request)
  { 
    $per_page = $request->get_param('per_page') ? intval($request->get_param('per_page')) : 5;
    $page = $request->get_param('page') ? intval($request->get_param('page')) : 1;

    $offset = ($page - 1) * $per_page;
    
     $posts = get_posts(array(
      'post_type' => 'post',
      'post_status' => 'publish',
      'posts_per_page' => $per_page,
      'offset'=> $offset,
    ));

    if (empty($posts)) {
      return new \WP_Error('no_posts', 'No posts found', array('status' => 404));
    }
    $data = array();
    foreach ($posts as $post) {
      $author_id = $post->post_author;
      $author_avatar_url = get_avatar_url($author_id, array('size' => 96));

      $thumbnail_url = get_the_post_thumbnail_url($post->ID, 'full');
      $user_info = get_userdata($author_id);
      $post_meta = get_post_meta($post->ID);
      $categories = get_the_terms($post->ID, 'category');
      $category_names = array();
      if ($categories && !is_wp_error($categories)) {
        foreach ($categories as $category) {
          $category_names[] = $category->name;
        }
      }
      $data[] = array(
        'id' => $post->ID,
        'title' => $post->post_title,
         'name'=>$user_info->display_name,
        //'content' => $post->post_content,
        'thumbnail_url' => $thumbnail_url,
        'author_id' => $author_id,
        'author_avatar_url' => $author_avatar_url,
        'created_at' => $post->post_date,
        'categories' => $category_names,
        //'meta' => $post_meta,
      );
    }

    return rest_ensure_response($data);
  }
}
$getblog = new getblog();

class GetBlogbyid
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'getblogbyid'));
    }
     function getblogbyid()
    {
    register_rest_route(
      'Voxel/v1',
      '/getblogbyid/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get'),
      )
    );
    }
    function get($request){
      $post_id = $request->get_param('id');

      $post = get_post($post_id);

      if (empty($post)) {
        return new \WP_Error('no_post', 'Post not found', array('status' => 404));
      }

      $author_id = $post->post_author;
      $author_avatar_url = get_avatar_url($author_id, array('size' => 96));
      $thumbnail_url = get_the_post_thumbnail_url($post->ID, 'full');
      $user_info = get_userdata($author_id);
      $post_meta = get_post_meta($post->ID);
      $categories = get_the_terms($post->ID, 'category');
      $category_names = array();
      if ($categories && !is_wp_error($categories)) {
        foreach ($categories as $category) {
          $category_names[] = $category->name;
        }
      }
      $timeline_entries = $this->get_timeline_entries($post_id);
      $data = array(
        'id' => $post->ID,
        'title' => $post->post_title,
        'content' => $post->post_content,
        'name' => $user_info->display_name,
        'thumbnail_url' => $thumbnail_url,
        'author_id' => $author_id,
        'author_avatar_url' => $author_avatar_url,
        'created_at' => $post->post_date,
        'categories' => $category_names,
        'timeline_entries' => $timeline_entries,
        'share' => get_permalink($post->ID),
        //'meta' => $post_meta,
      );

      return $data;

    }
    private function get_timeline_entries($post_id)
    {
      global $wpdb;
      $table_name = $wpdb->prefix . 'voxel_timeline';
      $results = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM $table_name WHERE post_id = %d ORDER BY created_at ASC", $post_id)
      );

      $entries = array();
      foreach ($results as $row) {
        $details_urls = array();
        if (!empty($row->details)) {
          $details_data = json_decode($row->details, true);
          if (isset($details_data['files'])) {
            $file_ids = explode(',', $details_data['files']);
            foreach ($file_ids as $file_id) {
              $details_urls[] = wp_get_attachment_url(trim($file_id));
            }
          }
        }

            // Retrieve user information
        $user_info = get_userdata($row->user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown User';
        $user_avatar_url = $user_info ? get_avatar_url($row->user_id, array('size' => 96)) : '';

        $entries[] = array(
          'id' => $row->id,
          'user_id' => $row->user_id,
          'user_name' => $user_name,
          'user_avatar_url' => $user_avatar_url,
          'published_as' => $row->published_as,
          'content' => $row->content,
          'details' => $details_urls,
          'review_score' => $row->review_score,
          'created_at' => $row->created_at,
          'edited_at' => $row->edited_at,
          );
      }

      return $entries;
    }
}
$GetBlogbyid =new GetBlogbyid();

class filterblog
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'filterblog'));
  }

  function filterblog()
  {
    register_rest_route(
      'Voxel/v1',
      '/filterblog/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get'),

      )
    );
  }
  function get($request)
  {
    $params = $request->get_param('id');
    $term_id = intval($request->get_param('id'));
    if (!$term_id) {
      return new \WP_Error('no_term_id', 'Term ID is required', array('status' => 400));
    }
    // If term ID is provided, use it to filter posts
    $args = array(
        'post_type' => 'post',
        'post_status' => 'publish',
        'posts_per_page' => -1,
        'tax_query' => array(
            array(
                'taxonomy' => 'category',
                'field' => 'term_id', // Filter by term ID
                'terms' => $term_id,
            ),
        ),
    );

    $loop = new \WP_Query($args);
   

    if (!$loop->have_posts()) {
      return new \WP_Error('no_posts', 'No posts found', array('status' => 404));
    }

    $data = array();
    while ($loop->have_posts()) {
      $loop->the_post();

      $post = $loop->post;
      $author_id = $post->post_author;
      $author_avatar_url = get_avatar_url($author_id, array('size' => 96));
      $user_info = get_userdata($author_id);

      $thumbnail_url = get_the_post_thumbnail_url($post->ID, 'full');
      $post_meta = get_post_meta($post->ID);
      $categories = get_the_terms($post->ID, 'category');
      $category_names = array();
      if ($categories && !is_wp_error($categories)) {
        foreach ($categories as $category) {
          $category_names[] = $category->name;
        }
      }
      $data[] = array(
        'id' => $post->ID,
        'title' => $post->post_title,
        'author_id' => $author_id,
        'name' => $user_info->display_name,
        'content' => $post->post_content,
        'thumbnail_url' => $thumbnail_url,
        'author_avatar_url' => $author_avatar_url,
        'created_at' => $post->post_date,
        'categories' => $category_names,
        //'meta' => $post_meta,
      );
    }

        // Reset the post data after custom query
    wp_reset_postdata();

    return rest_ensure_response($data);
  }
}
$filterblog = new filterblog();
class InsertTimelineComment
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    function register_routes()
    {
        register_rest_route(
            'Voxel/v1',
            '/insertcommentblog',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'insert_comment'),
        )       
        );
    }

    function insert_comment($request)
    {
        global $wpdb;

        $user_id = $request->get_param('user_id');
        $post_id = $request->get_param('post_id');
        $content = $request->get_param('content');
        $details = $request->get_param('details') ?? null;
        $review_score = $request->get_param('review_score') ?? null;

        if (empty($user_id) || empty($post_id) || empty($content)) {
            return rest_ensure_response(
                array(
                    'message' => 'Required fields are missing. Please ensure `user_id`, `post_id`, and `content` are provided.'
                )
            );
        }

        // Validate user
        $user = get_user_by('ID', $user_id);
        if (!$user) {
            return rest_ensure_response(
                array(
                    'message' => 'The specified user ID does not exist. Please provide a valid `user_id`.'
                )
            );
        }

        // Validate post
        $post = get_post($post_id);
        if (!$post) {
            return rest_ensure_response(
                array(
                    'message' => 'The specified post ID does not exist. Please provide a valid `post_id`.'
                )
            );
        }
        // Prepare details
        // $details_data = array();
        // if (!empty($details)) {
        //     $details_data = json_decode($details, true);
        // }

        // Prepare data for insertion
        $data = array(
            'user_id' => $user_id,
            'post_id' => $post_id,
            'content' => $content,
            'details' =>  null,
            'review_score' => $review_score,
            'created_at' => current_time('mysql'),
        );

        // Insert into the database
        $table_name = $wpdb->prefix . 'voxel_timeline';
        $inserted = $wpdb->insert($table_name, $data);

        if (!$inserted) {
            return new \WP_Error('db_insert_error', 'Failed to insert comment', array('status' => 500));
        }

        // Prepare response data
        $response_data = array(
            'message' => 'Your comment has been inserted successfully', // Confirmation message
        );

        return rest_ensure_response($response_data);
    }
}

$InsertTimelineComment = new InsertTimelineComment();


class postinsert
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'postinsert'));
    }

    function postinsert()
    {
        register_rest_route(
            'Voxel/v1',
            '/postinsert',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'insert_post'),
            )
        );
    }

    function insert_post($request)
    {   
        $params = $request->get_params();

        $post_title = sanitize_text_field($params['title'] ?? '');
        $post_author = $params['author'] ?? '';
        $post_content = $params['content'] ?? '';
        $email= $params['email'] ?? '';
        $post_slogan=$params['slogan'] ?? '';
        $phone= $params['phone']?? '';
        $address=$params['address'] ?? '';
        $latitude= $params['latitude'] ?? '';
        $longitude =$params['longitude'] ?? '';
        $facebook =$params['facebook']  ?? '';
        $twitter =$params['twitter']  ?? '';
        $instagram =$params['instagram'] ??'';
        $website =$params['website'] ?? '';
        $amenities =$params['amenities'] ?? array();
        $pricerange = $params['pricerange'] ?? '';
        $city = $params['city'] ?? array();
        $country= $params['country'] ??array();
        $LGBTQ =$params['LGBTQ'] ?? array();
        $places_category = $params['places_category'] ?? array(); 
        //$userInput = json_decode($params['user_input'] ?? '[]', true);
        $data = [];
        $post_author = get_user_by('id', $post_author);
        if (!$post_author) {
        return new \WP_Error('user_not_found', 'User not found or you are not authorrize.', array('status' => 404));
      }
       // Fix and decode user_input
      $userInput = $params['user_input'] ?? '[]';

      // Clean the user_input string to ensure it is valid JSON
      $userInput = str_replace(
        array('\\"', '“', '”', '\\\\', "'"),
        array('"', '"', '"', '\\', '"'),
        $userInput
      );

      // Remove leading/trailing quotes if necessary
      $userInput = trim($userInput, "'");
      // Decode JSON
      $decoded_input = json_decode($userInput, true);

      foreach ($decoded_input as $item) {
            $day = [
                'days' => $item['days'],
                'status' => $item['status'],
                'hours' => $item['hours']
            ];
            $data[] = $day;
        }
        $output = json_encode($data);
        //$post_status = $params['status'];
        $dynamic_address = array(
          'address' => $address,
          'map_picker' => !empty($latitude) && !empty($longitude) ? true : false,
          'latitude' => $latitude,
          'longitude' =>  $longitude
        );
        $social_media_links = json_encode(array(
          array("taxonomy" => ["facebook"], "url" => $facebook),
          array("taxonomy" => ["twitter"], "url" => $twitter),
          array("taxonomy" => ["instagram"], "url" => $instagram)
       ));
        $post_name= sanitize_title($params['name'] ?? '');
        $thumbnail_id = 0;
        if (!empty($_FILES['thumbnail_file']['tmp_name'])) {
          $file = $_FILES['thumbnail_file'];
          $thumbnail_id= $this->upload_file($file);
        }
        $logo_id = 0;
        if (!empty($_FILES['logo']['tmp_name'])) {
          $file = $_FILES['logo'];
          $logo_id= $this->upload_file($file);
        }
        $photo_ids = array();
        if (!empty($_FILES['photo_file']['tmp_name']) && is_array($_FILES['photo_file']['tmp_name'])) {
          foreach ($_FILES['photo_file']['tmp_name'] as $index => $tmp_name) {
              $file = array(
                  'name'     => $_FILES['photo_file']['name'][$index],
                  'type'     => $_FILES['photo_file']['type'][$index],
                  'tmp_name' => $tmp_name,
                  'error'    => $_FILES['photo_file']['error'][$index],
                  'size'     => $_FILES['photo_file']['size'][$index]
              );
              $photo_id = $this->upload_file($file);
              if ($photo_id) {
                  $photo_ids[] = $photo_id;
                  // $photo_ids['url'] = wp_get_attachment_url($photo_id);
              } else {
                  echo 'Error uploading photo at index ' . $index;
              }
          }
      }
      // var_dump($term_ids);
      // die;
      // Debug statements
      // echo 'Photo IDs: ';
      // print_r($photo_ids);
        $post_meta = $params['meta'] ?? array(); // Assuming 'meta' is an array of meta_key => meta_value pairss
        $post_meta['_thumbnail_id'] = $thumbnail_id; // Add thumbnail ID to post meta
        $post_meta['gallery'] = implode(',', $photo_ids); // Add photo ID to post meta
        $post_meta['email']= $email;
        $post_meta['phone'] = $phone;
        $post_meta['location'] = json_encode($dynamic_address);
        $post_meta['repeater-2'] =$social_media_links;
        $post_meta['work-hours'] =$output;
        $post_meta['website']  = $website;
        $post_meta['logo']= $logo_id;
        $post_meta['text'] =$post_slogan;
        
      
        
         $post_id = wp_insert_post(array(
            'post_author'=> $post_author,
            'post_title' => $post_title,
            'post_content' => $post_content,
            'post_name'=> $post_name,
            'post_status' => 'publish',
            'post_type' => 'places', // Adjust post type as needed
            'post_thumbnail' => $thumbnail_id,
        ));
     
        if (is_wp_error($post_id)) {
            return rest_ensure_response(array(
                'message' => 'Error creating post',
            ));
        }
        // $categories = is_array($params['categories']) ? array_map('intval', $params['categories']) : array();
        // var_dump($categories);
        // $amenities = !empty($params['amenities']) ? array_map('intval', $params['amenities']) : array();
        // wp_set_post_terms($post_id, $categories, 'places_category');
        // wp_set_post_terms($post_id, $amenities, 'amenities');
        // Add post meta
        if (!empty($amenities)) {
           $amenities_ids = $this->clean_term_ids($amenities);
            foreach ($amenities_ids as $amenity_id) {
            wp_set_post_terms($post_id, $amenity_id, 'amenities', true);
          }
          
      }

      if (!empty($places_category)) {
          $places_category_ids = $this->clean_term_ids($places_category);
          // var_dump($places_category_ids);die;
          foreach ($places_category_ids as $places_category_id) {
          wp_set_post_terms($post_id, $places_category_id, 'places_category',true);
          }
      }
      if (!empty($places_category)) {
        $places_category_ids = $this->clean_term_ids($places_category);
        // var_dump($places_category_ids);die;
        foreach ($places_category_ids as $places_category_id) {
        wp_set_post_terms($post_id, $places_category_id, 'places_category',true);
        }
      }
      if (!empty($pricerange)) {
       $pricerange= wp_set_post_terms($post_id, $pricerange, 'price_range', true);
      }
      if (!empty($LGBTQ)) {
        $LGBTQ = $this->clean_term_ids($LGBTQ);
        // var_dump($places_category_ids);die;
        foreach ($LGBTQ as $LGBTQ) {
        wp_set_post_terms($post_id, $LGBTQ, 'restaurant-tags',true);
        }
      }
      if (!empty($city)) {
        $city = $this->clean_term_ids($city);
        // var_dump($places_category_ids);die;
        foreach ($city as $city) {
        wp_set_post_terms($post_id, $city, 'city',true);
        }
      }
      if (!empty($country)) {
        $country = $this->clean_term_ids($country);
        // var_dump($places_category_ids);die;
        foreach ($country as $country) {
        wp_set_post_terms($post_id, $country, 'city',true);
        }
      }
       if (!empty($post_meta) && is_array($post_meta)) {
            foreach ($post_meta as $key => $value) {
                update_post_meta($post_id, $key, $value);
            }
        }
        $this->insert_custom_table_data($post_id, $post_title, $post_content, $params);
        return rest_ensure_response(array(
            'message' => 'Post created successfully',
            'post_id' => $post_id,
        ));
    }
  private function upload_file($file)
  {
    $upload_dir = wp_upload_dir();
    $file_name = basename($file['name']);
    $file_path = $upload_dir['path'] . '/' . $file_name;

    if (move_uploaded_file($file['tmp_name'], $file_path)) {
        $attachment = array(
            'post_title' => $file_name,
            'post_content' => '',
            'post_status' => 'inherit',
            'post_mime_type' => $file['type']
        );

        $attachment_id = wp_insert_attachment($attachment, $file_path);
        if (!is_wp_error($attachment_id)) {
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $attachment_data = wp_generate_attachment_metadata($attachment_id, $file_path);
            wp_update_attachment_metadata($attachment_id, $attachment_data);
            return $attachment_id;
        }
    }
  }
  private function clean_term_ids($term_ids) {
    // Remove unwanted characters and return an array of clean IDs
    $term_ids = str_replace(array('[', ']', '"', "'"), '', $term_ids);
    return explode(',', $term_ids);
  }
   private function insert_custom_table_data($post_id, $post_title, $post_content, $params)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'voxel_index_places'; // Change to your table name
        $post_status = 'publish';
        $keywords = $post_title ?? '';
        $latitude = $params['latitude'] ?? '';
        $longitude = $params['longitude'] ?? '';
        $rating = null;
        $date_created = current_time('mysql');

     // Prepare SQL query to insert spatial data using ST_GeomFromText
      $sql = $wpdb->prepare("
        INSERT INTO $table_name 
        (post_id, post_status, _keywords, _location, rating, date_created)
        VALUES (%d, %s, %s, ST_GeomFromText(%s), %d, %s)",
        $post_id, $post_status, $keywords, "POINT($longitude $latitude)", $rating, $date_created
    );

    }
}

$postinsert = new postinsert();

class placeupdate
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'placeupdate'));
  }

  function placeupdate()
  {
    register_rest_route(
      'Voxel/v1',
      '/placeupdate',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'update_place'),
      )
    );
  }
  function update_place($request){
    $params = $request->get_params();
    $post_id = isset($params['post_id']) ? intval($params['post_id']) : 0;

    $post_title = sanitize_text_field($params['title'] ?? '');
    $post_author = $params['author'] ?? '';
    $post_content = $params['content'] ?? '';
    $email = $params['email'] ?? '';
    $post_slogan = $params['slogan'] ?? '';
    $phone = $params['phone'] ?? '';
    $address = $params['address'] ?? '';
    $latitude = $params['latitude'] ?? '';
    $longitude = $params['longitude'] ?? '';
    $facebook = $params['facebook'] ?? '';
    $twitter = $params['twitter'] ?? '';
    $instagram = $params['instagram'] ?? '';
    $website = $params['website'] ?? '';
    $amenities = $params['amenities'] ?? array();
    $pricerange = $params['pricerange'] ?? '';
    $city = $params['city'] ?? array();
    $country = $params['country'] ?? array();
    $LGBTQ = $params['LGBTQ'] ?? array();
    $places_category = $params['places_category'] ?? array();
    $userInput = $params['user_input'] ?? '[]';
    $data = [];
    if (!$post_id) {
      return new \WP_Error('no_post_id', 'No post ID provided.', array('status' => 400));
    }

    $post_author = get_user_by('id', $post_author);
    if (!$post_author) {
      return new \WP_Error('user_not_found', 'User not found or you are not authorized.', array('status' => 404));
    }

    if(!empty($params['user_input'])){
        // Clean and decode user_input
      $userInput = str_replace(
        array('\\"', '“', '”', '\\\\', "'"),
        array('"', '"', '"', '\\', '"'),
        $userInput
      );
      $userInput = trim($userInput, "'");
      $decoded_input = json_decode($userInput, true);

      foreach ($decoded_input as $item) {
        $day = [
          'days' => $item['days'],
          'status' => $item['status'],
          'hours' => $item['hours']
        ];
        $data[] = $day;
      }
      $output = json_encode($data);
    }
       // $post_name = sanitize_title($params['name'] ?? '');
    $thumbnail_id = 0;
    if (!empty($_FILES['thumbnail_file']['tmp_name'])) {
      $file = $_FILES['thumbnail_file'];
      $thumbnail_id = $this->upload_file($file);
    }

    $logo_id = 0;
    if (!empty($_FILES['logo']['tmp_name'])) {
      $file = $_FILES['logo'];
      $logo_id = $this->upload_file($file);
    }

    $photo_ids = array();
    if (!empty($_FILES['photo_file']['tmp_name']) && is_array($_FILES['photo_file']['tmp_name'])) {
      foreach ($_FILES['photo_file']['tmp_name'] as $index => $tmp_name) {
        $file = array(
          'name'     => $_FILES['photo_file']['name'][$index],
          'type'     => $_FILES['photo_file']['type'][$index],
          'tmp_name' => $tmp_name,
          'error'    => $_FILES['photo_file']['error'][$index],
          'size'     => $_FILES['photo_file']['size'][$index]
        );
        $photo_id = $this->upload_file($file);
        if ($photo_id) {
          $photo_ids[] = $photo_id;
        } else {
          echo 'Error uploading photo at index ' . $index;
        }
      }
    }

        $post_meta = $params['meta'] ?? array(); // Assuming 'meta' is an array
        if (!empty($thumbnail_id)) {
          $post_meta['_thumbnail_id'] = $thumbnail_id; // Add thumbnail ID to post meta
        }

        if (!empty($photo_ids)) {
          $post_meta['gallery'] = implode(',', $photo_ids); // Add photo ID to post meta
        }

        if (!empty($email)) {
          $post_meta['email'] = $email;
        }

        if (!empty($phone)) {
          $post_meta['phone'] = $phone;
        }

        $existing_address = get_post_meta($post_id, 'location', true);
        if ($existing_address) {
          $existing_address = json_decode($existing_address, true);
        } else {
          $existing_address = array();
        } 
       // Update only if incoming values are not empty
        if (!empty($address)) {
         $existing_address['address'] = $address ?? '';
       }
       if (!empty($latitude) && !empty($longitude)) {
        $existing_address['latitude'] = $latitude ??'';
        $existing_address['longitude'] = $longitude ?? '';
        $existing_address['map_picker'] = true;
      }
      $post_meta['location'] = json_encode($existing_address);

      
      if (!empty($params['user_input'])) {
        $post_meta['work-hours'] = $output;
      }
      
      if (!empty($params['website'])) {
        $post_meta['website'] = $website;
      }
      $social_media_links_json = get_post_meta($post_id, 'repeater-2', true);
      if($social_media_links_json){
        $social_media_links = json_decode($social_media_links_json, true) ?? [];

        $existing_links = [
          "facebook" => "",
          "twitter" => "",
          "instagram" => ""
        ];

      // Store existing links
        foreach ($social_media_links as $link) {
          if (isset($link['taxonomy'][0])) {
            $taxonomy = $link['taxonomy'][0];
            $existing_links[$taxonomy] = $link['url'] ?? '';
          }
        }

      // Example input for changing social media URLs
        $new_facebook = $facebook?? '';
        $new_twitter = $twitter ?? '';
        $new_instagram = $instagram ??'';

        $updated_links = [];

        if (!empty($new_facebook)) {
          $existing_links['facebook'] = $new_facebook;
        }
        if (!empty($new_twitter)) {
          $existing_links['twitter'] = $new_twitter;
        }
        if (!empty($new_instagram)) {
          $existing_links['instagram'] = $new_instagram;
        }

      // Re-encode the updated social media links
        foreach ($existing_links as $taxonomy => $url) {
          if (!empty($url)) {
            $updated_links[] = array("taxonomy" => [$taxonomy], "url" => $url);
          }
        }

        $post_meta['repeater-2'] = json_encode($updated_links);
      }
      if (!empty($logo_id)) {
        $post_meta['logo'] = $logo_id;
      }
      if(!empty($post_slogan)){
        $post_meta['text']=$post_slogan;
      }
      $post_arr = array(
        'ID' => $post_id,
      );
      
      // Add only non-empty values to the $post_arr array(post)
      if (!empty($post_author)) {
        $post_arr['post_author'] = $post_author;
      }
      if (!empty($params['title'])) {
        $post_arr['post_title'] = $params['title'];
      }
      
      if (!empty($post_content)) {
        $post_arr['post_content'] = $post_content;
      }
      
      if (!empty($params['title'])) {
        $post_name = sanitize_title($params['title']);
        $name = $this->stringToSlug($post_name);
        $post_arr['post_name'] = $name;
      }
      
      $post_arr['post_status'] = 'publish';
      $post_arr['post_type'] = 'places';
      
      if (!empty($thumbnail_id)) {
        $post_arr['post_thumbnail'] = $thumbnail_id;
      }
      
      $post_id = wp_update_post($post_arr);
      
      if (is_wp_error($post_id)) {
        return rest_ensure_response(array(
          'message' => 'Error updating post',
        ));
      }

      //taxonomy adding//
      if (!empty($amenities)) {
        wp_set_post_terms($post_id, array(), 'amenities');
        $amenities_ids = $this->clean_term_ids($amenities);
        foreach ($amenities_ids as $amenity_id) {
         wp_set_post_terms($post_id, $amenity_id, 'amenities', true);
       }
     }

     if (!empty($places_category)) {
      wp_set_post_terms($post_id, array(), 'places_category');
      $places_category_ids = $this->clean_term_ids($places_category);
      foreach ($places_category_ids as $places_category_id) {
       wp_set_post_terms($post_id, $places_category_id, 'places_category',true);
     }
   }

   if (!empty($pricerange)) {
    wp_set_post_terms($post_id, array(), 'price_range');
    $pricerange= wp_set_post_terms($post_id, $pricerange, 'price_range', true);
  }

  if (!empty($LGBTQ)) {
   wp_set_post_terms($post_id, array(), 'restaurant-tags');
   $LGBTQ = $this->clean_term_ids($LGBTQ);
   foreach ($LGBTQ as $LGBTQ) {
     wp_set_post_terms($post_id, $LGBTQ, 'restaurant-tags',true);
   }
 }

 if (!empty($city)) {
   wp_set_post_terms($post_id, array(), 'city');
   $city = $this->clean_term_ids($city);
   foreach ($city as $city) {
     wp_set_post_terms($post_id, $city, 'city',true);
   }
 }
 if (!empty($country)) {
   wp_set_post_terms($post_id, array(), 'city');
   $country = $this->clean_term_ids($country);
   foreach ($country as $country) {
     wp_set_post_terms($post_id, $country, 'city',true);
   }
 }
 if (!empty($post_meta) && is_array($post_meta)) {
   foreach ($post_meta as $key => $value) {
     update_post_meta($post_id, $key, $value);
   }
 }
 return rest_ensure_response(array(
  'message' => 'place  update successfully',
  'post_id' => $post_id,
));
}
private function upload_file($file)
{
 $upload_dir = wp_upload_dir();
 $file_name = basename($file['name']);
 $file_path = $upload_dir['path'] . '/' . $file_name;

 if (move_uploaded_file($file['tmp_name'], $file_path)) {
   $attachment = array(
     'post_title' => $file_name,
     'post_content' => '',
     'post_status' => 'inherit',
     'post_mime_type' => $file['type']
   );
   
   $attachment_id = wp_insert_attachment($attachment, $file_path);
   if (!is_wp_error($attachment_id)) {
     require_once(ABSPATH . 'wp-admin/includes/image.php');
     $attachment_data = wp_generate_attachment_metadata($attachment_id, $file_path);
     wp_update_attachment_metadata($attachment_id, $attachment_data);
     return $attachment_id;
   }
 }

}
function stringToSlug($string)
{
           // Convert the string to lowercase
 $slug = strtolower($string);

           // Replace any non-alphanumeric characters with a hyphen
 $slug = preg_replace('/[^a-z0-9]+/i', '-', $slug);

           // Trim hyphens from the beginning and end of the string
 $slug = trim($slug, '-');

 return $slug;
}
private function clean_term_ids($term_ids) {
        // Remove unwanted characters and return an array of clean IDs
  $term_ids = str_replace(array('[', ']', '"', "'"), '', $term_ids);
  return explode(',', $term_ids);
}
}
$placeupdate =new placeupdate();

class placeDelete
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'place_delete_route'));
  }

  function place_delete_route()
  {
    register_rest_route(
      'Voxel/v1',
      '/placedelete',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'delete_place'),
      )
    );
  }

  function delete_place($request)
  {
    $params = $request->get_params();
    $post_id = isset($params['post_id']) ? intval($params['post_id']) : 0;

    if (!$post_id) {
      return new \WP_Error('no_post_id', 'No post ID provided.', array('status' => 400));
    }

    $post = get_post($post_id);

    if (!$post || $post->post_type !== 'places') {
      return new \WP_Error('invalid_post', 'Invalid post ID.', array('status' => 404));
    }

    $result = wp_delete_post($post_id, true); // The second parameter, true, means force delete (bypasses trash)

    if (!$result) {
      return rest_ensure_response(array(
        'message' => 'Error deleting post',
      ));
    }

    return rest_ensure_response(array(
      'message' => 'Place deleted successfully',
      'post_id' => $post_id,
    ));
  }
}

$placeDelete =new placeDelete();
// Api for eventinsert
class evetinsert
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'evetinsert'));
    }

    function evetinsert()
    {
        register_rest_route(
            'Voxel/v1',
            '/evetinsert',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'insert_event'),
            )
        );
    }

    function insert_event($request)
    {   
        $params = $request->get_params();

        $event_title = sanitize_text_field($params['eventName'] ?? '');
        $event_author = $params['author'] ?? '';
        $event_content = $params['content'] ?? '';
        $email= $params['email'] ?? '';
        $phone= $params['phone']?? '';
        $address=$params['address'] ?? '';
        $latitude= $params['latitude'] ?? '';
        $longitude =$params['longitude'] ?? '';
        $website =$params['website'] ?? '';
        $city = $params['city'] ?? array();
        $country= $params['country'] ??array();
        $event_pricing =$params['price'] ?? array();
        $event_category = $params['eventCat'] ?? array(); 
        $event_host= $params['hostedBy'];
        $startDate  =$params['startDate'] ?? null;
        $startTime =$params['startTime']  ?? null;
        $endDate   =$params['endDate'] ?? null;
        $endTime  = $params['endTime']  ?? null;
        $recurrence = $params['recurrence'] ;
        $untilDate = $params['untilDate'] ?? null;
        $frequency = intval($params['daysreq'] ?? 1);
        $url=$params['eventUrl'] ??'';
        //$userInput = json_decode($params['user_input'] ?? '[]', true);
        $data = [];
        $event_author= get_user_by('id', $event_author);
        if (!$event_author) {
        return new \WP_Error('user_not_found', 'User not found or you are not authorrize.', array('status' => 404));
        }
         $dynamic_address = array(
          'address' => $address,
          'map_picker' => true,
          'latitude' => $latitude,
          'longitude' =>  $longitude
        );
        $recurrence = json_decode($params['recurrence'] ?? '', true);
        if ($startDate && $startTime && $endTime) {
        $start_date = $startDate . ' ' . $startTime;
        $end_date = $endDate ? $endDate . ' ' . $endTime : $startDate . ' ' . $endTime;

        // Default schedule data without recurrence
        $schedule_data = array(array(
            'start' => $start_date,
            'end' => $end_date,
         ));

        if ($recurrence) {
            // Mapping recurrence labels to units
            $recurrence_mapping = array(
                'Daily' => 'day',
                'Weekly' => 'week',
                'Monthly' => 'month',
                'Yearly' => 'year'
            );

            $label = $recurrence['label'];
            if (array_key_exists($label, $recurrence_mapping)) {
                $unit = $recurrence_mapping[$label];
                $schedule_data = array(array(
                    'start' => $start_date,
                    'end' => $end_date,
                    'frequency' => $frequency,
                    'unit' => $unit,
                    'until' => $untilDate
                ));
            }
        }
        }
        $output =json_encode($schedule_data);
        $post_name= sanitize_title($params['eventName'] ?? '');
        $name=$this->stringToSlug($post_name);
       
        
        $thumbnail_id = 0;
        if (!empty($_FILES['thumbnail_file']['tmp_name'])) {
          $file = $_FILES['thumbnail_file'];
          $thumbnail_id= $this->upload_file($file);
        }
        $logo_id = 0;
        if (!empty($_FILES['logo']['tmp_name'])) {
          $file = $_FILES['logo'];
          $logo_id= $this->upload_file($file);
        }
        $photo_ids = array();
        if (!empty($_FILES['photo_file']['tmp_name']) && is_array($_FILES['photo_file']['tmp_name'])) {
          foreach ($_FILES['photo_file']['tmp_name'] as $index => $tmp_name) {
              $file = array(
                  'name'     => $_FILES['photo_file']['name'][$index],
                  'type'     => $_FILES['photo_file']['type'][$index],
                  'tmp_name' => $tmp_name,
                  'error'    => $_FILES['photo_file']['error'][$index],
                  'size'     => $_FILES['photo_file']['size'][$index]
              );
              $photo_id = $this->upload_file($file);
              if ($photo_id) {
                  $photo_ids[] = $photo_id;
                  // $photo_ids['url'] = wp_get_attachment_url($photo_id);
              } else {
                  echo 'Error uploading photo at index ' . $index;
              }
          }
      }
      // var_dump($term_ids);
      // die;
      // Debug statements
      // echo 'Photo IDs: ';
      // print_r($photo_ids);
        $post_meta = $params['meta'] ?? array(); // Assuming 'meta' is an array of meta_key => meta_value pairss
        $post_meta['_thumbnail_id'] = $thumbnail_id; // Add thumbnail ID to post meta
        $post_meta['gallery'] = implode(',', $photo_ids); // Add photo ID to post meta
        $post_meta['email']= $email;
        $post_meta['phone'] = $phone;
        $post_meta['location'] = json_encode($dynamic_address);
        $post_meta['event_date'] =$output;
        $post_meta['website']  = $website;
        $post_meta['logo']= $logo_id;
        if(!empty($url)){
          $post_meta['switcher']= 1;
          $post_meta['url']=$url;
        }
        
      
        
         $post_id = wp_insert_post(array(
            'post_author'=> $event_author,
            'post_title' => $event_title,
            'post_content' => $event_content,
            'post_name'=> $name,
            'post_status' => 'publish',
            'post_type' => 'events', // Adjust post type as needed
            'post_thumbnail' => $thumbnail_id,
        ));
     
        if (is_wp_error($post_id)) {
            return rest_ensure_response(array(
                'message' => 'Error creating post',
            ));
        }
        // $categories = is_array($params['categories']) ? array_map('intval', $params['categories']) : array();
        // var_dump($categories);
        // $amenities = !empty($params['amenities']) ? array_map('intval', $params['amenities']) : array();
        // wp_set_post_terms($post_id, $categories, 'places_category');
        // wp_set_post_terms($post_id, $amenities, 'amenities');
        // Add post meta
       

      if (!empty($event_category)) {
          $event_category = $this->clean_term_ids($event_category);
          // var_dump($places_category_ids);die;
          wp_set_post_terms($post_id, $event_category, 'events-category',true);

      }

      if (!empty($event_pricing)) {
       $event_pricing= wp_set_post_terms($post_id, $event_pricing, 'event-pricing', true);
      }
      if (!empty($city)) {
        $city = $this->clean_term_ids($city);
        // var_dump($places_category_ids);die;
        foreach ($city as $city) {
        wp_set_post_terms($post_id, $city, 'city',true);
        }
      }
      if (!empty($country)) {
        $country = $this->clean_term_ids($country);
        // var_dump($places_category_ids);die;
        foreach ($country as $country) {
        wp_set_post_terms($post_id, $country, 'city',true);
        }
      }
       if (!empty($post_meta) && is_array($post_meta)) {
            foreach ($post_meta as $key => $value) {
                update_post_meta($post_id, $key, $value);
            }
        }
        global $wpdb;
        if(!empty($event_host)){
        $data = array(
          'child_id' => $post_id,
          'parent_id' => $event_host,
          'relation_key' => 'event-place',
          'order' => 0 
      );
        $inserted = $wpdb->insert(
          $wpdb->prefix . 'voxel_relations',
          $data,
          array('%d', '%d', '%s')
      );
      }
      if($post_id){
      // Retrieve the JSON encoded schedule data from post meta
      $json_data = get_post_meta($post_id, 'event_date', true);
      }
      if($json_data){
      // Decode the JSON data
      $schedule_data = json_decode($json_data, true);
      }
      if($schedule_data['frequency']){
        foreach ($schedule_data as $schedule) {
          // Adjust frequency if unit is 'week' by converting to days
          if ($schedule['unit'] === 'week') {
              $schedule['frequency'] *= 7;
              $schedule['unit'] = 'day'; // Change unit to 'day'
          }
          elseif ($schedule['unit'] === 'year') {
            $schedule['frequency'] *= 12;
            $schedule['unit'] = 'month'; // Change unit to 'month'
          } 
      
          $wpdb->insert(
              $wpdb->prefix . 'voxel_recurring_dates',
              [
                  'post_id' => $post_id,
                  'start' => $schedule['start'],
                  'end' => $schedule['end'],
                  'frequency' => $schedule['frequency'],
                  'unit' => $schedule['unit'],
                  'until' => $schedule['until'],
                  'field_key' => 'event_date',
                  'post_type' => 'events'
              ],
              [
                  '%d', // post_id as integer
                  '%s', // start as string
                  '%s', // end as string
                  '%d', // frequency as integer
                  '%s', // unit as string
                  '%s' ,// until as string
                  '%s', // field_key as string
                  '%s'  // post_type as string
              ]
          );
        }
      }
      if ($inserted === false) {
      return new \WP_REST_Response('db_insert_error', 'Failed to insert host');
      }
       $this->insert_custom_table_data($post_id, $event_title, $event_content, $params);
        return rest_ensure_response(array(
            'message' => 'event created successfully',
            'events_id' => $post_id,
        ));
    }
  private function upload_file($file)
  {
    $upload_dir = wp_upload_dir();
    $file_name = basename($file['name']);
    $file_path = $upload_dir['path'] . '/' . $file_name;

    if (move_uploaded_file($file['tmp_name'], $file_path)) {
        $attachment = array(
            'post_title' => $file_name,
            'post_content' => '',
            'post_status' => 'inherit',
            'post_mime_type' => $file['type']
        );

        $attachment_id = wp_insert_attachment($attachment, $file_path);
        if (!is_wp_error($attachment_id)) {
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $attachment_data = wp_generate_attachment_metadata($attachment_id, $file_path);
            wp_update_attachment_metadata($attachment_id, $attachment_data);
            return $attachment_id;
        }
    }
  }
  private function clean_term_ids($term_ids) {
    // Remove unwanted characters and return an array of clean IDs
    $term_ids = str_replace(array('[', ']', '"', "'"), '', $term_ids);
    return explode(',', $term_ids);
}
function stringToSlug($string) {
  // Convert the string to lowercase
  $slug = strtolower($string);
  
  // Replace any non-alphanumeric characters with a hyphen
  $slug = preg_replace('/[^a-z0-9]+/i', '-', $slug);
  
  // Trim hyphens from the beginning and end of the string
  $slug = trim($slug, '-');
  
  return $slug;
}
   private function insert_custom_table_data($post_id, $event_title, $event_content, $params)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'voxel_index_events'; // Change to your table name
        $post_status = 'publish';
        $keywords = $event_title ?? '';
        $latitude = $params['latitude'] ?? '';
        $longitude = $params['longitude'] ?? '';
        $rating = null;
        $date_created = current_time('mysql');

     // Prepare SQL query to insert spatial data using ST_GeomFromText
      $sql = $wpdb->prepare("
        INSERT INTO $table_name 
        (post_id, post_status, _keywords, _location,  date_created)
        VALUES (%d, %s, %s, ST_GeomFromText(%s),  %s)",
        $post_id, $post_status, $keywords, "POINT($longitude $latitude)", $rating, $date_created
    );

    }
}

$evetinsert = new evetinsert();

class evetupdate
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'evetupdate'));
    }

    function evetupdate()
    {
        register_rest_route(
            'Voxel/v1',
            '/evetupdate',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'update_event'),
            )
        );
    }

    function update_event($request)
    {
        $params = $request->get_params();

        $event_title = sanitize_text_field($params['title'] ?? '');
        $event_author = $params['author'] ?? '';
        $event_content = $params['content'] ?? '';
        $email = $params['email'] ?? '';
        $phone = $params['phone'] ?? '';
        $address = $params['address'] ?? '';
        $latitude = $params['latitude'] ?? '';
        $longitude = $params['longitude'] ?? '';
        $website = $params['website'] ?? '';
        $city = $params['city'] ?? array();
        $country = $params['country'] ?? array();
        $event_pricing = $params['event_pricing'] ?? array();
        $event_category = $params['event_category'] ?? array(); 
        $event_host = $params['event_host'] ?? '';
        $post_id = $params['post_id'] ?? 0;
        $url=$params['url'] ??''; // For updating existing post

        if (!$post_id) {
            return new \WP_Error('no_post_id', 'No post ID provided.', array('status' => 400));
        }

        $event_author = get_user_by('id', $event_author);
        if (!$event_author) {
            return new \WP_Error('user_not_found', 'User not found or you are not authorized.', array('status' => 404));
        }

        // Fix and decode user_input
        $userInput = $params['user_input'] ?? '[]';
        if(!empty($params['user_input'])){
        $userInput = str_replace(array('\\"', '“', '”', '\\\\', "'"), array('"', '"', '"', '\\', '"'), $userInput);
        $userInput = trim($userInput, "'");
        $decoded_input = json_decode($userInput, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
          return rest_ensure_response(array(
            'message' => 'Error json string',
        ));
        }

        $data = [];
        foreach ($decoded_input as $item) {
            $schedule = [
                'start' => $item['start'],
                'end' => $item['end'],
                'frequency' => $item['frequency'],
                'unit' => $item['unit'],
                'until' => $item['until']
            ];
            $data[] = $schedule;
        }
       $output = json_encode($data);
       }
       
    
       

        $thumbnail_id = 0;
        if (!empty($_FILES['thumbnail_file']['tmp_name'])) {
            $file = $_FILES['thumbnail_file'];
            $thumbnail_id = $this->upload_file($file);
        }

        $logo_id = 0;
        if (!empty($_FILES['logo']['tmp_name'])) {
            $file = $_FILES['logo'];
            $logo_id = $this->upload_file($file);
        }

        $photo_ids = array();
        if (!empty($_FILES['photo_file']['tmp_name']) && is_array($_FILES['photo_file']['tmp_name'])) {
            foreach ($_FILES['photo_file']['tmp_name'] as $index => $tmp_name) {
                $file = array(
                    'name'     => $_FILES['photo_file']['name'][$index],
                    'type'     => $_FILES['photo_file']['type'][$index],
                    'tmp_name' => $tmp_name,
                    'error'    => $_FILES['photo_file']['error'][$index],
                    'size'     => $_FILES['photo_file']['size'][$index]
                );
                $photo_id = $this->upload_file($file);
                if ($photo_id) {
                    $photo_ids[] = $photo_id;
                } else {
                    echo 'Error uploading photo at index ' . $index;
                }
            }
        }
      
        $post_meta = $params['meta'] ?? array(); // Assuming 'meta' is an array of meta_key => meta_value pairs
        if (!empty($thumbnail_id)) {
          $post_meta['_thumbnail_id'] = $thumbnail_id; // Add thumbnail ID to post meta
        }
      
        if (!empty($photo_ids)) {
          $post_meta['gallery'] = implode(',', $photo_ids); // Add photo ID to post meta
       }
      
      if (!empty($email)) {
          $post_meta['email'] = $email;
      }
      
      if (!empty($phone)) {
          $post_meta['phone'] = $phone;
      }
      
      $existing_address = get_post_meta($post_id, 'location', true);
          if ($existing_address) {
          $existing_address = json_decode($existing_address, true);
            } else {
                $existing_address = array();
            }

            // Update only if incoming values are not empty
            if (!empty($address)) {
                $existing_address['address'] = $address ?? '';
            }
            if (!empty($latitude) && !empty($longitude)) {
                $existing_address['latitude'] = $latitude ??'';
                $existing_address['longitude'] = $longitude ?? '';
                $existing_address['map_picker'] = true;
            }
       $post_meta['location'] = json_encode($existing_address);
    
      
      if (!empty($params['user_input'])) {
          $post_meta['event_date'] = $output;
      }
      
      if (!empty($params['website'])) {
          $post_meta['website'] = $website;
      }
      
      if (!empty($logo_id)) {
          $post_meta['logo'] = $logo_id;
      }
      if(!empty($url)){
          $post_meta['switcher']= 1;
          $post_meta['url']=$url;
      }
      $post_arr = array(
        'ID' => $post_id,
      );
    
    // Add only non-empty values to the $post_arr array
    if (!empty($event_author)) {
        $post_arr['post_author'] = $event_author;
    }
    // $post_name = sanitize_title( ?? '');
    // $name = $this->stringToSlug($post_name);
    if (!empty($params['title'])) {
        $post_arr['post_title'] = $params['title'];
    }
    
    if (!empty($event_content)) {
        $post_arr['post_content'] = $event_content;
    }
    
    if (!empty($params['title'])) {
        $post_name = sanitize_title($params['title']);
        $name = $this->stringToSlug($post_name);
        $post_arr['post_name'] = $name;
    }
    
    $post_arr['post_status'] = 'publish';
    $post_arr['post_type'] = 'events';
    
    if (!empty($thumbnail_id)) {
        $post_arr['post_thumbnail'] = $thumbnail_id;
    }
    
    $post_id = wp_update_post($post_arr);

        if (is_wp_error($post_id)) {
            return rest_ensure_response(array(
                'message' => 'Error updating post',
            ));
        }

        if (!empty($event_category)) {
            wp_set_post_terms($post_id, array(), 'events-category');
            $event_category = $this->clean_term_ids($event_category);
            wp_set_post_terms($post_id, $event_category, 'events-category', true);
        }

        if (!empty($event_pricing)) {
          wp_set_post_terms($post_id, array(), 'event-pricing');
          wp_set_post_terms($post_id, $event_pricing, 'event-pricing', true);
        }

        if (!empty($city)) {
          wp_set_post_terms($post_id, array(), 'city');
            $city = $this->clean_term_ids($city);
            foreach ($city as $city) {
                wp_set_post_terms($post_id, $city, 'city', true);
            }
        }

        if (!empty($country)) {
          wp_set_post_terms($post_id, array(), 'city');
            $country = $this->clean_term_ids($country);
            foreach ($country as $country) {
                wp_set_post_terms($post_id, $country, 'city', true);
            }
        }

        if (!empty($post_meta) && is_array($post_meta)) {
            foreach ($post_meta as $key => $value) {
                update_post_meta($post_id, $key, $value);
            }
        }

        global $wpdb;
        $existing_relation = null;
        if(!empty($event_host)){
        $data = array(
            'child_id' => $post_id,
            'parent_id' => $event_host,
            'relation_key' => 'event-place',
            'order' => 0 
        );

        $existing_relation = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}voxel_relations WHERE child_id = %d AND parent_id = %d AND relation_key = %s",
            $post_id, $event_host, 'event-place'
        ));
        } 
        if ($existing_relation) {
            $wpdb->update(
                $wpdb->prefix . 'voxel_relations',
                $data,
                array('child_id' => $post_id, 'parent_id' => $event_host, 'relation_key' => 'event-place'),
                array('%d', '%d', '%s')
            );
        } 

        if ($post_id) {
            // Retrieve the JSON encoded schedule data from post meta
            $json_data = get_post_meta($post_id, 'event_date', true);
        }

        if ($json_data) {
            // Decode the JSON data
            $schedule_data = json_decode($json_data, true);
        }

        
        if (!empty($params['user_input'])) {
        foreach ($schedule_data as $schedule) {
         // Adjust frequency if unit is 'week' by converting to days
        if ($schedule['unit'] === 'week') {
          $schedule['frequency'] *= 7;
          $schedule['unit'] = 'day'; // Change unit to 'day'
        } elseif ($schedule['unit'] === 'year') {
          $schedule['frequency'] *= 12;
          $schedule['unit'] = 'month'; // Change unit to 'month'
        }
      
          // Prepare the data for update or insert
      $data = [
          'post_id' => $post_id,
          'start' => $schedule['start'],
          'end' => $schedule['end'],
          'frequency' => $schedule['frequency'],
          'unit' => $schedule['unit'],
          'until' => $schedule['until'],
          'field_key' => 'event_date',
          'post_type' => 'events'
      ];

      // Check if the record exists
      $existing = $wpdb->get_row($wpdb->prepare(
          "SELECT * FROM {$wpdb->prefix}voxel_recurring_dates WHERE post_id = %d AND start = %s AND field_key = %s",
          $post_id, $schedule['start'], 'event_date'
      ));

      if ($existing) {
          // Update the existing record
          $wpdb->update(
              $wpdb->prefix . 'voxel_recurring_dates',
              $data,
              array('post_id' => $post_id, 'start' => $schedule['start'], 'field_key' => 'event_date',),
              array('%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s'),
              array('%d', '%s', '%s')
          );
      } else {
          // Insert a new record
          $wpdb->insert(
              $wpdb->prefix . 'voxel_recurring_dates',
              $data,
              array('%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s')
          );
      }
      }
      }
      return rest_ensure_response(array(
            'message' => 'event updated successfully',
            'events_id' => $post_id,
        ));
    }

    private function upload_file($file)
    {
        $upload_dir = wp_upload_dir();
        $file_name = basename($file['name']);
        $file_path = $upload_dir['path'] . '/' . $file_name;

        if (move_uploaded_file($file['tmp_name'], $file_path)) {
            $attachment = array(
                'post_title' => $file_name,
                'post_content' => '',
                'post_status' => 'inherit',
                'post_mime_type' => $file['type']
            );

            $attachment_id = wp_insert_attachment($attachment, $file_path);
            if (!is_wp_error($attachment_id)) {
                require_once(ABSPATH . 'wp-admin/includes/image.php');
                $attachment_data = wp_generate_attachment_metadata($attachment_id, $file_path);
                wp_update_attachment_metadata($attachment_id, $attachment_data);
                return $attachment_id;
            }
        }
    }

    private function clean_term_ids($term_ids)
    {
        // Remove unwanted characters and return an array of clean IDs
        $term_ids = str_replace(array('[', ']', '"', "'"), '', $term_ids);
        return explode(',', $term_ids);
    }

    function stringToSlug($string)
    {
        // Convert the string to lowercase
        $slug = strtolower($string);

        // Replace any non-alphanumeric characters with a hyphen
        $slug = preg_replace('/[^a-z0-9]+/i', '-', $slug);

        // Trim hyphens from the beginning and end of the string
        $slug = trim($slug, '-');

        return $slug;
    }
}

$evetupdate = new evetupdate();

class evetdelete
{
    function __construct()
    {
        add_action('rest_api_init', array($this, 'evetdelete'));
    }

    function evetdelete()
    {
        register_rest_route(
            'Voxel/v1',
            '/evetdelete',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'delete_event'),
            )
        );
    }
    function delete_event($request) {
      global $wpdb;
  
      $post_id = (int) $request->get_param('id');
      $post = get_post($post_id);
      
      if (is_null($post)) {
          return new  \WP_REST_Response(array('message' =>'no_events_found', 'data'=>'events not found'));
      }
  
      //  recurring dates associated with the event
      $wpdb->delete(
          $wpdb->prefix . 'voxel_recurring_dates',
          array(
              'post_id' => $post_id,
              'post_type' => 'events'
          ),
          array(
              '%d',
              '%s'
          )
      );
  
      // custom relationships associated with the event
      $wpdb->delete(
          $wpdb->prefix . 'voxel_relations',
          array(
              'child_id' => $post_id,
              'relation_key' => 'event-place'
          ),
          array(
              '%d',
              '%s'
          )
      );
  
      // Delete the post meta associated with the event
      $wpdb->delete(
          $wpdb->prefix . 'postmeta',
          array(
              'post_id' => $post_id
          ),
          array(
              '%d'
          )
      );
  
      // 4. Delete the event post itself
      $deleted = wp_delete_post($post_id, true); // Second argument true to force delete
  
      if ($deleted) {
          return rest_ensure_response(array(
              'message' => 'Event deleted successfully',
              'event_id' => $post_id,
          ));
      } else {
          return new \WP_Error('delete_failed', 'Failed to delete event', array('status' => 500));
      }
  }
  }
  $evetdelete = new evetdelete();


  class message
{
  function __construct()
  {
      add_action('rest_api_init', array($this, 'message'));
  }


function message() {
  
  register_rest_route( 'Voxel/v1', '/send-message', array(
      'methods' => 'POST',
      'callback' => array($this, 'send_message_to_recipient'),
  ) );

  register_rest_route( 'Voxel/v1', '/get-messages', array(
      'methods' => 'POST',
      'callback' =>  array($this, 'get_messages'),
  ) );
   register_rest_route( 'Voxel/v1', '/delete-messages', array(
    'methods' => 'POST',
    'callback' =>  array($this, 'delete_message'),
) );
}

function send_message_to_recipient( $request ) {
  $params = $request->get_params();
  $response = array();
  $sender_id = isset($params['sender_id']) ? sanitize_text_field($params['sender_id']) : null;
  $receiver_id = isset($params['receiver_id']) ? sanitize_text_field($params['receiver_id']) : null;
  if (!$sender_id || !$receiver_id) {
    return new \WP_REST_Response(array('message'=>'missing_parameters'));
  }
  $sender_type = 'user';
  $receiver_type = 'user';
  $sender = get_user_by('id', $sender_id);
  if (!$sender) {
    $sender = get_post($sender_id);
    if ($sender && $sender->post_type === 'places') {
      $sender_type = 'post';
    } else {
      return new \WP_REST_Response(array('message' => 'Sender not found'));
    }
  }

  $receiver = get_user_by('id', $receiver_id);
  if (!$receiver) {
    $receiver = get_post($receiver_id);
    if ($receiver && $receiver->post_type === 'places') {
      $receiver_type = 'post';
    } else {
      return new \WP_REST_Response(array('message' => 'Receiver not found'));
    }
  }

    // Handle file upload
  if (!empty($_FILES['file'])) {
    $file = $_FILES['file'];
    $attachment_id = $this->upload_file($file);
    if (!is_wp_error($attachment_id)) {
      $file_url = wp_get_attachment_url($attachment_id);
            //$response['file_url'] = $file_url;

            // Insert the message into the database
      global $wpdb;
      $table_name = $wpdb->prefix . 'voxel_messages';
      $wpdb->insert(
        $table_name,
        array(
          'sender_id' => sanitize_text_field($params['sender_id']),
          'receiver_id' => sanitize_text_field($params['receiver_id']),
          'sender_type'=>$sender_type,
          // 'content' => sanitize_text_field($params['message']),
          'receiver_type'=> $receiver_type,
          'details' => '{"files":"' . $attachment_id . '"}',
          'created_at' => current_time('mysql'),
        )
      );
       $message_id = $wpdb->insert_id;

    // Retrieve or create the chat record
    $results = $wpdb->get_results($wpdb->prepare(
        "SELECT id, p1_type, p1_id, p2_type, p2_id FROM {$wpdb->prefix}voxel_chats
        WHERE (p1_type = %s AND p1_id = %d AND p2_type = %s AND p2_id = %d)
        OR (p1_type = %s AND p1_id = %d AND p2_type = %s AND p2_id = %d)",
        $sender_type, $sender_id, $receiver_type, $receiver_id,
        $receiver_type, $receiver_id, $sender_type, $sender_id
    ));

    if (count($results)) {
        $chat = array_shift($results);

        // Only 1 chat can exist between the same two parties
        if (!empty($results)) {
            $ids = array_map('absint', array_column($results, 'id'));
            $delete_ids = join(',', array_filter($ids));
            if (!empty($delete_ids)) {
                $wpdb->query("DELETE FROM {$wpdb->prefix}voxel_chats WHERE id IN ({$delete_ids})");
            }
        }

        $sender_column = ($chat->p1_type === $sender_type && absint($chat->p1_id) === $sender_id) ? 'p1_last_message_id' : 'p2_last_message_id';

        // Update the existing chat
        $chat_id = absint($chat->id);
        $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}voxel_chats
            SET last_message_id = %d, {$sender_column} = %d
            WHERE id = %d",
            $message_id, $message_id, $chat_id
        ));
    } else {
        // Create a new chat record
        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$wpdb->prefix}voxel_chats (p1_type, p1_id, p1_last_message_id, p2_type, p2_id, p2_last_message_id, last_message_id)
            VALUES (%s, %d, %d, %s, %d, 0, %d)",
            $sender_type, $sender_id, $message_id, $receiver_type, $receiver_id, $message_id
        ));
     }
      $response['message'] = 'Message and file sent successfully.';

    }
  } elseif (isset($params['message'])) {
        // Insert the message into the database without a file
    global $wpdb;
    $table_name = $wpdb->prefix . 'voxel_messages';
    $wpdb->insert(
      $table_name,
      array(
        'sender_id' => sanitize_text_field($params['sender_id']),
        'receiver_id' => sanitize_text_field($params['receiver_id']),
        'sender_type'=>$sender_type,
        'receiver_type'=> $receiver_type,
        'content' => sanitize_text_field($params['message']),
        'details' => null,  
        'created_at' => current_time('mysql'),
      )
    );
     $message_id = $wpdb->insert_id;

    // Retrieve or create the chat record
    $results = $wpdb->get_results($wpdb->prepare(
        "SELECT id, p1_type, p1_id, p2_type, p2_id FROM {$wpdb->prefix}voxel_chats
        WHERE (p1_type = %s AND p1_id = %d AND p2_type = %s AND p2_id = %d)
        OR (p1_type = %s AND p1_id = %d AND p2_type = %s AND p2_id = %d)",
        $sender_type, $sender_id, $receiver_type, $receiver_id,
        $receiver_type, $receiver_id, $sender_type, $sender_id
    ));

    if (count($results)) {
        $chat = array_shift($results);

        // Only 1 chat can exist between the same two parties
        if (!empty($results)) {
            $ids = array_map('absint', array_column($results, 'id'));
            $delete_ids = join(',', array_filter($ids));
            if (!empty($delete_ids)) {
                $wpdb->query("DELETE FROM {$wpdb->prefix}voxel_chats WHERE id IN ({$delete_ids})");
            }
        }

        $sender_column = ($chat->p1_type === $sender_type && absint($chat->p1_id) === $sender_id) ? 'p1_last_message_id' : 'p2_last_message_id';

        // Update the existing chat
        $chat_id = absint($chat->id);
        $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}voxel_chats
            SET last_message_id = %d, {$sender_column} = %d
            WHERE id = %d",
            $message_id, $message_id, $chat_id
        ));
    } else {
        // Create a new chat record
        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$wpdb->prefix}voxel_chats (p1_type, p1_id, p1_last_message_id, p2_type, p2_id, p2_last_message_id, last_message_id)
            VALUES (%s, %d, %d, %s, %d, 0, %d)",
            $sender_type, $sender_id, $message_id, $receiver_type, $receiver_id, $message_id
        ));
    }
    $response['message'] = 'Message sent successfully.';
  }else {
    return new \WP_Error('invalid_params', 'Either a file or a message is required.', array('status' => 400));
  }

  return $response;
}

function get_messages( $request ) {
     global $wpdb;

    // Get user IDs from the POST request
    $user_id = $request->get_param('user_id');
    $other_user_id = $request->get_param('other_user_id');

    if (empty($user_id) || empty($other_user_id)) {
        return new \WP_Error('missing_parameters', 'Missing user_id or other_user_id', array('status' => 400));
    }

    $table_name = $wpdb->prefix . 'voxel_messages';

    $query = $wpdb->prepare(
        "SELECT * FROM $table_name 
        WHERE 
        (sender_id = %d AND receiver_id = %d) OR 
        (sender_id = %d AND receiver_id = %d)
        ORDER BY created_at ASC",
        $user_id, $other_user_id, $other_user_id, $user_id
    );

    $messages = $wpdb->get_results($query);

    if (empty($messages)) {
        return new \WP_Error('no_messages', 'No messages found between the specified users', array('status' => 404));
    }
    $sender_photo_url = null;
    if($this->is_user($user_id)){
      $sender_photo_url = get_avatar_url($user_id, 'profile_photo', true);
    }
    elseif ($this->is_post($user_id)) {
        $sender_photo_url = $this->get_post_logo_url($user_id);
    }
    $receiver_photo_url = null;

    if ($this->is_user($other_user_id)) {
        $receiver_photo_url = get_avatar_url($other_user_id, 'profile_photo', true);
    } elseif ($this->is_post($other_user_id)) {
        $receiver_photo_url = $this->get_post_logo_url($other_user_id);
    }

    // Structure the messages into sent and received arrays with parsed details
    foreach ($messages as $message) {
        // Parse the details JSON
       if ($message->sender_id == $user_id) {
            $message->photo_url = $sender_photo_url;
        } else {
            $message->photo_url = $receiver_photo_url;
        }
      if ( ! empty( $message->details ) ) {
        $details = json_decode($message->details, true);

        // Add the file URL to the message if it exists
        if (isset($details['files'])) {
            $file_id = $details['files'];
            $message->details = $this->get_file_url($file_id);
        }
      }
    }

    return rest_ensure_response($messages);
   
}
function delete_message( $request) {
  global $wpdb;

  $message_id = $request->get_param('message_id');

  if (empty($message_id)) {
      return new \WP_Error('missing_parameters', 'Missing message_id', array('status' => 400));
  }
  $table_name = $wpdb->prefix . 'voxel_messages';
  
  $message = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE id = %d", $message_id
    ));

  if (!$message) {
      return new \WP_Error('not_found', 'Message not found', array('status' => 404));
  }
  $result = $wpdb->delete($table_name, array('id' => $message_id));

  if ($result === false) {
      return new \WP_Error('delete_failed', 'Failed to delete message or not found', array('status' => 500));
  }

  return new \WP_REST_Response('Message deleted successfully', 200);
}
private function upload_file($file)
{
    $upload_dir = wp_upload_dir();
    $file_name = $file_name = time() . '-' . basename($file['name']);
    $file_path = $upload_dir['path'] . '/' . $file_name;

    if (move_uploaded_file($file['tmp_name'], $file_path)) {
        $attachment = array(
            'post_title' => $file_name,
            'post_content' => '',
            'post_status' => 'inherit',
            'post_mime_type' => $file['type']
        );

        $attachment_id = wp_insert_attachment($attachment, $file_path);
        if (!is_wp_error($attachment_id)) {
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $attachment_data = wp_generate_attachment_metadata($attachment_id, $file_path);
            wp_update_attachment_metadata($attachment_id, $attachment_data);
            return $attachment_id;
        }
    }
}
// private function get_file_url( $file_id ) {
//   // Implement this function based on your file storage configuration
//   // For example, if your files are stored in the uploads directory, you can use wp_get_attachment_url
//   return wp_get_attachment_url( $file_id );
// }
function is_user($id) {
    $user = get_user_by('ID', $id);
    return $user !== false;
}

function is_post($id) {
    $post = get_post($id);
    return $post !== null && $post->post_type === 'places';
}

function get_post_logo_url($post_id) {
    $logo_id = get_post_meta($post_id, 'logo', true);
    return wp_get_attachment_url($logo_id);
}

function get_file_url($file_id) {
    return wp_get_attachment_url($file_id);
}
}
$message = new message();

class Collection_Relations {
  function __construct() {
      add_action('rest_api_init', array($this, 'register_routes'));
  }
  function register_routes() {
  
    register_rest_route( 'Voxel/v1', '/collections/(?P<user_id>\d+)', array(
        'methods' => 'GET',
        'callback' => array($this, 'send_message_to_recipient'),
    ) );
  }
    function send_message_to_recipient( $request ) {
      global $wpdb;

      // Get user_id from request
      $user_id = intval($request->get_param('user_id'));

      // Fetch collection posts by user ID
      $collections = get_posts(array(
          'post_type' => 'collection',
          'post_status' => 'publish',
          'posts_per_page' => -1,
          'author' => $user_id,
      ));
      
      if (empty($collections)) {
          return new \WP_Error('no_collections_found', 'No collections found for the specified user.', array('status' => 404));
      }
      $post_ids = array();
        foreach ($collections as $collection) {
            $post_ids[] = $collection->ID;
        }
      if (!empty($post_ids)) {
          $placeholders = implode(', ', array_fill(0, count($post_ids), '%d'));
          $query = $wpdb->prepare(
            "SELECT parent_id, child_id FROM wp_voxel_relations WHERE parent_id IN ($placeholders)",
            $post_ids
        );
      
      $related_posts = $wpdb->get_results($query);
      $relations = array();
      foreach ($related_posts as $relation) {
        $relations[$relation->parent_id][] = $relation->child_id;
    }
     foreach ($collections as $collection) {
      $collection_id = $collection->ID;
      $formatted_collections[] = array(
          'id' => $collection_id,
          'title' => $collection->post_title,
          'related_post_ids' => $this->get_related_post_details($relations[$collection_id] ?? array()),
      );
     }
    }

  return $formatted_collections;
}
private function get_related_post_details($post_ids) {
  global $wpdb;

  $formatted_posts = array();

  foreach ($post_ids as $post_id) {
    $post = get_post($post_id);

    if ($post) {
      $featured_image_id = get_post_thumbnail_id($post_id);
      $featured_image_url = '';
      if ($featured_image_id) {
        $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
        if (is_array($featured_image_data)) {
          $featured_image_url = $featured_image_data[0];
        }
      }

      $profile_logo_id = get_post_meta($post_id, 'logo', true);
      $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';

      $address = get_post_meta($post_id, 'location', true);
      $address_data = json_decode($address, true);

      $review_stats_json = get_post_meta($post_id, 'voxel:review_stats', true);
      if ($review_stats_json) {
        $review_stats = json_decode($review_stats_json, true);
        $total_reviews = isset($review_stats['total']) ? $review_stats['total'] : 0;
        $average_rating = isset($review_stats['average']) ? round($review_stats['average'] + 3, 2) : 0;
      } else {
        $total_reviews = 0;
        $average_rating = 0;
      }

      $address = isset($address_data['address']) ? $address_data['address'] : '';
      $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
      $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';
      $opening_hours_data = get_post_meta($post_id, 'work-hours', true);
      $opening_hours = json_decode($opening_hours_data, true);

      $formatted_opening_hours = array();
      if (!empty($opening_hours) && is_array($opening_hours)) {
        foreach ($opening_hours as $hours_data) {
          $days = $hours_data['days'] ?? array();
          $status = $hours_data['status'] ?? 'hours';
          $hours = $hours_data['hours'] ?? array();
          foreach ($days as $day) {
            if (!isset($formatted_opening_hours[$day])) {
              $formatted_opening_hours[$day] = array();
            }
            if ($status === 'closed') {
              $formatted_opening_hours[$day][] = 'Closed all day';
            } elseif ($status === 'appointments_only') {
              $formatted_opening_hours[$day][] = 'Appointments Only';
            } elseif (!empty($hours)) {
              foreach ($hours as $hour) {
                $formatted_opening_hours[$day][] = $hour['from'] . '-' . $hour['to'];
              }
            } else {
              $formatted_opening_hours[$day][] = 'Open all day';
            }
          }
        }
      }

      $formatted_posts[] = array(
        'id' => $post_id,
        'name' => $post->post_title,
        'content' => $post->post_content,
        'featured_image_url' => $featured_image_url,
        'profile_logo_url' => $profile_logo_url,
        'address' => $address,
        'latitude' => $latitude,
        'longitude' => $longitude,
        'total_reviews' => $total_reviews,
        'average_rating' => $average_rating,
        'opening_hours' => $formatted_opening_hours,
      );
    }
  }
  return $formatted_posts;
}
}
$Collection_Relations = new Collection_Relations();

class ids{
  function __construct() {
      add_action('rest_api_init', array($this, 'register_routes'));
  }
  function register_routes() {
  
    register_rest_route( 'Voxel/v1', '/userid/(?P<email>[^/]+)', array(
        'methods' => 'GET',
        'callback' => array($this, 'get_userid'),
    ) );
  }
  function get_userid( $request ) {
   $email = sanitize_email($request->get_param('email'));
   $user = get_user_by('email', $email);

   if (!$user) {
       return new \WP_Error('user_not_found', 'No user found with the provided email address.', array('status' => 404));
   }

   $user_id = $user->ID;
   $user_id=array(
     "user_id" => $user_id,
   );
   return $user_id;
 }
}
$ids = new ids();

class location{
 
  function __construct() {
    add_action('rest_api_init', array($this, 'location'));
  }
function location() {
    
   register_rest_route( 'Voxel/v1', '/location/(?P<user_id>\d+)', array(
      'methods' => 'GET',
      'callback' => array($this, 'getuserdetails'),
  ) );
}
function getuserdetails($request ){
       global $wpdb;

      // Get user_id from request
      $user_id = intval($request->get_param('user_id'));

      // Fetch collection posts by user ID
      $locations = get_posts(array(
          'post_type' => 'profile',
          'post_status' => 'publish',
          'posts_per_page' => -1,
          'author' => $user_id,
      ));
     
      
        // Initialize location variable
        $location = null;

        // Loop through locations and find the first one
        foreach ($locations as $loc) {
            $location = $loc;
            break; // Break after finding the first location
        }
        $post_id = $location->ID;
        // Fetch location from wp_voxel_index_profile
        $table_name = 'wp_voxel_index_profile'; // Replace with your table name
        $location_query = $wpdb->prepare("SELECT ST_X(_location) AS latitude, ST_Y(_location) AS longitude, _keywords FROM $table_name WHERE post_id = %d", $post_id);
        $location_data = $wpdb->get_row($location_query);
        if (!$location_data) {
          return new \WP_Error('no_location_found', 'No location found for the specified post.', array('status' => 404));
        }
      $user_meta= get_user_meta($user_id);
      if(empty($user_meta)){
         return new \WP_Error('no_user_data_found', 'No user_data found for the specified user.', array('status' => 404));
      }
      
      $response = array(
        'location' => array(
            // 'ID' => $location_data->id,
            // 'post_id' => $location_data->post_id,
            //'post_status' => $location_data->post_status,
            '_keywords' => $location_data->_keywords,
            'latitude' => $location_data->latitude,
            'longitude' => $location_data->longitude
        )
    );
    return rest_ensure_response($response, 200);
}
}
$location =new location();

class getallumap {
  function __construct() {
    add_action('rest_api_init', array($this, 'getallumap'));
  }

  function getallumap() {
    register_rest_route(
      'Voxel/v1',
      '/getallumap',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }

  function getall() {
    $users = get_users();
    
    if (empty($users)) {
      return new \WP_Error('no_users_found', 'No users found.', array('status' => 404));
    }
    
    $user_data = array();
    foreach ($users as $user) {
      $user_id = $user->ID;
      $user_name = $user->display_name;
      $profile_pic_url = get_avatar_url($user_id);
      $bio = get_the_author_meta('description', $user_id);
      $locations = get_posts(array(
        'post_type' => 'profile',
        'post_status' => 'publish',
        'posts_per_page' => -1,
        'author' => $user_id,
      ));

      $location = null;
      foreach ($locations as $loc) {
        $location = $loc;
        break; // Break after finding the first location
      }

      if ($location) {
        $post_id = $location->ID;
        // Fetch location from wp_voxel_index_profile
        global $wpdb;
        $table_name = 'wp_voxel_index_profile'; // Replace with your table name
        $location_query = $wpdb->prepare("SELECT ST_X(_location) AS latitude, ST_Y(_location) AS longitude, _keywords FROM $table_name WHERE post_id = %d", $post_id);
        $location_data = $wpdb->get_row($location_query);

        if ($location_data && !empty($location_data->latitude) && !empty($location_data->longitude)) {
          $user_info = array(
            'id' => $user_id,
            'name' => $user_name,
            'profile_pic_url' => $profile_pic_url,
            'bio' => $bio,
            '_keywords' => $location_data->_keywords,
            'latitude' => $location_data->latitude,
            'longitude' => $location_data->longitude,
          );

          $user_data[] = $user_info;
        }
      }
    }
    
    return rest_ensure_response($user_data);
  }
}

$getallumap = new getallumap();

class updateimage{
  function __construct()
    {
        add_action('rest_api_init', array($this, 'updateimage'));
    }

     function updateimage()
    {
        register_rest_route(
            'Voxel/v1',
            '/updateimage',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'image'),
            )
        );
    }
    function image($request){
    $params = $request->get_params();
    $post_id = isset($params['post_id']) ? intval($params['post_id']) : 0;
    $profile_post = get_post($post_id);
    if (!$profile_post) {
        return new \WP_Error('invalid_post_id', 'Invalid post ID.', array('status' => 400));
    }
    $files = $request->get_file_params('gallery');
  //  var_dump(($files));die;

    if (empty($files['gallery']['name'][0])) {
      return new \WP_Error('no_image', 'Image not found.', array('status' => 400));
    }
    
    $uploaded_file_ids = array();
    if (!empty($files['gallery']) && is_array($files['gallery'])) {
     $file_count = count($files['gallery']['name']);
     for ($i = 0; $i < $file_count; $i++) {
         $file = array(
             'name' => $files['gallery']['name'][$i],
             'type' => $files['gallery']['type'][$i],
             'tmp_name' => $files['gallery']['tmp_name'][$i],
             'error' => $files['gallery']['error'][$i],
             'size' => $files['gallery']['size'][$i],
         );

         $uploaded_file = wp_handle_upload($file, array('test_form' => false));
         if (isset($uploaded_file['file'])) {
             $file_name = basename($uploaded_file['file']);
             $attachment = array(
                 'guid' => $uploaded_file['url'],
                 'post_mime_type' => $uploaded_file['type'],
                 'post_title' => preg_replace('/\.[^.]+$/', '', $file_name),
                 'post_content' => '',
                 'post_status' => 'inherit'
             );
             $attachment_id = wp_insert_attachment($attachment, $uploaded_file['file']);
             if (!is_wp_error($attachment_id)) {
                 require_once(ABSPATH . 'wp-admin/includes/image.php');
                 $attachment_data = wp_generate_attachment_metadata($attachment_id, $uploaded_file['file']);
                 wp_update_attachment_metadata($attachment_id, $attachment_data);
                 $uploaded_file_ids[] = $attachment_id;
             }
         }
     }
   }
   $merged_gallery_ids = array();
   if (!empty($uploaded_file_ids)) {
     $existing_gallery_ids_string = get_post_meta($post_id, 'gallery', true);

     $existing_gallery_ids = !empty($existing_gallery_ids_string) ? explode(',', $existing_gallery_ids_string) : array();
 
     $total_gallery_images = count($existing_gallery_ids) + count($uploaded_file_ids);
     if ($total_gallery_images <= 10) {
         $merged_gallery_ids = array_slice(array_merge($existing_gallery_ids, $uploaded_file_ids), 0, 10);
         update_post_meta($post_id, 'gallery', implode(',', $merged_gallery_ids));
     } else {
         return new \WP_Error('gallery_limit_exceeded', 'Gallery image limit exceeded (max: 10)', array('status' => 400));
     }
    }
    return new \WP_REST_Response(array(
      'message' => 'Location updated successfully',
       'gallery_ids' => $merged_gallery_ids
     ), 200);
    }

}
$updateimage = new updateimage();

class LocationUpdate
{
     function __construct()
    {
        add_action('rest_api_init', array($this, 'location'));
    }

     function location()
    {
        register_rest_route(
            'Voxel/v1',
            '/locationupdate',
            array(
                'methods' => 'POST',
                'callback' => array($this, 'locationupdate'),
            )
        );
    }

     function locationupdate($request)
    {
        $params = $request->get_params();
        $post_id = isset($params['post_id']) ? intval($params['post_id']) : 0;
        $address = $params['address'] ?? '';
        $latitude = $params['latitude'] ?? '';
        $longitude = $params['longitude'] ?? '';
        $country = sanitize_text_field($params['country'] ?? '');
        $city = sanitize_text_field($params['city'] ?? '');
        $profile_post = get_post($post_id);

        if (!$profile_post) {
            return new \WP_Error('invalid_post_id', 'Invalid post ID.', array('status' => 400));
        }

        $dynamic_address = array(
            'address' => $address,
            'map_picker' => true,
            'latitude' => $latitude,
            'longitude' => $longitude
        );

        update_post_meta($post_id, 'location', json_encode($dynamic_address));
        // var_dump(term_exists($country->term_id)) ;
        //  die;
        if (!empty($country)) {
            $country = get_term_by('name',$country, 'city');
            if (!$country->term_id) {
               wp_insert_term($country, 'city');
            }
             wp_set_post_terms($post_id, $country->term_id, 'city', true);
        }

        if (!empty($city)) {
            $city =  get_term_by('name',$city, 'city');
            if (!$city->term_id) {
                wp_insert_term($city, 'city');
            }
             wp_set_post_terms($post_id, $city->term_id, 'city', true);
        }

        return new \WP_REST_Response(array(
            'message' => 'Location updated successfully'
        ), 200);
    }
}

$LocationUpdate = new LocationUpdate();

class profilebio{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'profilebio'));
  }
  function profilebio(){
    register_rest_route(
      'Voxel/v1',
      '/profilebio',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'profilebioupdate'),
      )
    );
  }
  function profilebioupdate($request){
    $params = $request->get_params();
    $content =$params['content'] ?? '';
    $post_id = isset($params['post_id']) ? intval($params['post_id']) : 0;
    $profile_post = get_post($post_id);
    if (!$profile_post) {
        return new \WP_Error('invalid_post_id', 'Invalid post ID.', array('status' => 400));
    }
    wp_update_post(array(
      'ID' => $post_id,
      'post_content' => $content,
      'post_status' => 'publish'
  ));
  
  return new \WP_REST_Response(array(
    'message' => 'profile bio update successfully'
), 200);
  }
}
$profilebio =new profilebio();

class profileupdate
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'profileupdate'));
  }
  function profileupdate(){
    register_rest_route(
      'Voxel/v1',
      '/deleteimage',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'delete_profile'),
      )
    );
  }
  function delete_profile($request){
    $params = $request->get_params();
    $post_id = isset($params['post_id']) ? intval($params['post_id']) : 0;
    $profile_post = get_post($post_id);
    if (!$profile_post) {
        return new \WP_Error('invalid_post_id', 'Invalid post ID.', array('status' => 400));
    }
  
    $image_ids = $params['image_ids']? $params['image_ids'] : array();

    if (count($image_ids)=== 0) {
        return new \WP_Error('no_image_ids', 'No image IDs provided.', array('status' => 400));
    }

    $gallery_ids_string = get_post_meta($post_id, 'gallery', true);
    $gallery_ids = !empty($gallery_ids_string) ? explode(',', $gallery_ids_string) : array();

    // Remove the specified image IDs from the existing gallery IDs
    foreach ($image_ids as $image_id_input) {
        $image_ids_to_remove = explode(',', $image_id_input);
        $gallery_ids = array_diff($gallery_ids, $image_ids_to_remove);
    }
    
    // Update the gallery meta field with the remaining IDs
    update_post_meta($post_id, 'gallery', implode(',', $gallery_ids));
    
    // Delete the specified images
    foreach ($image_ids as $image_id) {
        wp_delete_attachment($image_id, true);
    }

    return new \WP_REST_Response(array(
        'message' => 'Selected gallery images deleted successfully',
        'gallery_ids'=> $gallery_ids
    ), 200);
  }
}
$profileupdate = new profileupdate();

class getprofile
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'getprofile'));
  }

  function getprofile()
  {
    register_rest_route(
      'Voxel/v1',
      '/getprofile/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get_profile'),
      )
    );
  }
  function get_profile($request){
    $profile_id = $request->get_param('id');

    $user_id = $request->get_param('id');

    // Fetch profile post by user ID
    $profile_query = new \WP_Query(array(
      'post_type' => 'profile',
      'author' => $user_id,
      'posts_per_page' => 1,
    ));

    if (!$profile_query->have_posts()) {
      return new \WP_REST_Response(array('message' =>'no_data_found', 'data'=>'Something working'));
    }
    $user = get_userdata($user_id);
    $profile_post = $profile_query->posts[0];
    $profile_id = $profile_post->ID;
      // Get the thumbnail URL
      $thumbnail_id = get_post_thumbnail_id($profile_id);
      $thumbnail_url = $thumbnail_id ? wp_get_attachment_url($thumbnail_id) : '';
      // Get the avatar URL
      $avatar_id = get_user_meta($profile_post->post_author, 'voxel:avatar', true);
      $avatar_url = $avatar_id ? wp_get_attachment_url($avatar_id) : '';

      // Get the gallery URLs
      // Get the gallery URLs
      $gallery_meta = get_post_meta($profile_id, 'gallery', true);

    // Ensure $gallery_meta is a string before using explode()
      if (is_array($gallery_meta)) {
        $gallery_ids = array_map('intval', $gallery_meta);
      } else {
        $gallery_ids = explode(',', $gallery_meta);
      }

      $gallery_urls = array();
      foreach ($gallery_ids as $gallery_id) {
        $gallery_url = wp_get_attachment_url($gallery_id);
        if ($gallery_url) {
          $gallery_urls[] = $gallery_url;
        }
      }


      global $wpdb;

      $query = "
          SELECT t.name, tt.taxonomy
          FROM {$wpdb->term_relationships} tr
          INNER JOIN {$wpdb->term_taxonomy} tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
          INNER JOIN {$wpdb->terms} t ON tt.term_id = t.term_id
          WHERE tr.object_id = %d
      ";
  
      $terms = $wpdb->get_results($wpdb->prepare($query, $profile_id));
  
     $cities = array();
      $countries = array();
    //  var_dump($terms);
    //  die;
   if (!empty($terms)) {
      if (isset($terms[0])) {
          $countries[] = $terms[0]->name;
      }
      if (isset($terms[1])) {
          $cities[] = $terms[1]->name;
      }
    }
      
      $location_meta = get_post_meta($profile_id, 'location', true);
      $height= get_post_meta($profile_id,'height',true);
      $weight= get_post_meta($profile_id,'weight',true);
      $location_data = json_decode($location_meta, true);
      $profile_data = array(
        'id' => $profile_id,
        'content' => $profile_post->post_content ?? '',
        'name'=>$user->display_name ,
        'address' => $location_data['address'] ?? '',
        'latitude' => $location_data['latitude'] ?? '',
        'longitude' => $location_data['longitude'] ?? '',
        'map_picker'=> $location_data['map_picker'] ?? '',
        'city'=> $cities ?? '',
        'country'=>$countries ?? '',
        'thumbnail' => $thumbnail_url,
        'avatar' => $avatar_url,
        'gallery' => $gallery_urls,
        'height'=>$height ?? '',
        'weight'=>$weight ??'',
    );
   

    return new \WP_REST_Response($profile_data, 200);
  }
}
$getprofile = new getprofile();

class  createprofile
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'createprofile'));
  }

  function createprofile()
  {
    register_rest_route(
      'Voxel/v1',
      '/createprofile',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'profile'),
      )
    );
  }
  function profile($request){
     // Get request parameters
     
    // Get request parameters
    $params = $request->get_params();
    $content = isset($params['content']) ? sanitize_textarea_field($params['content']) : '';
    $address = isset($params['address']) ? $params['address'] : '';
    $map_picker = isset($params['map_picker']) ? $params['map_picker'] : false;
    $latitude = isset($params['latitude']) ? $params['latitude'] : '';
    $longitude = isset($params['longitude']) ? $params['longitude'] : '';
    $post_author = isset($params['id']) ? $params['id'] : '';
    $new_display_name = isset($params['name']) ? $params['name'] : '';
    $country = isset($params['country']) ? sanitize_text_field($params['country']) : '';
    $city = isset($params['city']) ? sanitize_text_field($params['city']) : '';
    $height = isset($params['height']) ? $params['height'] : '';
    $weight = isset($params['weight']) ? $params['weight'] : '';

    $user = get_user_by('id', $post_author);
    if (!$user) {
        return new \WP_Error('user_not_found', 'User not found.', array('status' => 404));
    }

    $user_data = array(
        'ID' => $post_author,
        'display_name' => $new_display_name,
    );

    wp_update_user($user_data);

    // Check if a profile post already exists for the user
    $existing_profile_args = array(
        'author' => $post_author,
        'post_type' => 'profile',
        'posts_per_page' => 1
    );

    $existing_profile_query = new \WP_Query($existing_profile_args);

    if ($existing_profile_query->have_posts()) {
        // Update the existing profile post
        $existing_profile_query->the_post();
        $post_id = get_the_ID();
        

        // Update post content if provided
        if (!empty($content)) {
          wp_update_post(array(
            'ID' => $post_id,
            'post_content' => $content,
            'post_status' => 'publish'
          ));
        }
          
            $existing_address = get_post_meta($post_id, 'location', true);
            if ($existing_address) {
                $existing_address = json_decode($existing_address, true);
            } else {
                $existing_address = array();
            }

            // Update only if incoming values are not empty
            if (!empty($address)) {
                $existing_address['address'] = $address;
            }
            if (!empty($latitude) && !empty($longitude)) {
                $existing_address['latitude'] = $latitude ?? 42.5;
                $existing_address['longitude'] = $longitude ?? 21.0;
                $existing_address['map_picker'] = true;
            }
            // Update post meta
            update_post_meta($post_id, 'location', json_encode($existing_address));
          
    } else {
        // Create a new profile post
        $post_id = wp_insert_post(array(
            'post_content' => $content,
            'post_status' => 'publish',
            'post_author' => $post_author,
            'post_type' => 'profile'
        ));

        if (is_wp_error($post_id)) {
            return new \WP_Error('post_creation_failed', 'Failed to create post', array('status' => 500));
        }
    }
   
      // Handle thumbnail and avatar uploads
    $thumbnail_id = 0;
    if (!empty($_FILES['thumbnail_file']['tmp_name'])) {
      $file = $_FILES['thumbnail_file'];
      $thumbnail_id = $this->upload_file($file);
      if (is_wp_error($thumbnail_id)) {
            return $thumbnail_id; // Return WP_Error
          }
          update_post_meta($post_id, '_thumbnail_id', $thumbnail_id);
        }

        $avatar_id = 0;
        if (!empty($_FILES['avatar']['tmp_name'])) {
          $file = $_FILES['avatar'];
          $avatar_id = $this->upload_file($file);

          if (is_wp_error($avatar_id)) {
           // Retrieve specific error message from WP_Error
            $error_message = $avatar_id->get_error_message();
            return new \WP_REST_Response(
              array(
                'code'    => 'avatar_upload_failed',
                'message' => $error_message, // Display specific error message
              ), // HTTP status code for bad request
          );
          }

         // Update user meta with the uploaded avatar ID
          update_user_meta($post_author, 'voxel:avatar', $avatar_id);
        }


        if (!empty($height)) {
            update_post_meta($post_id, 'height', $height);
        }
        if (!empty($weight)) {
            update_post_meta($post_id, 'weight', $weight);
        }
        // Handle image uploads
        if (isset($_FILES['gallery']) && is_array($_FILES['gallery']['name'])) {
          $files = $_FILES['gallery'];
          $uploaded_file_ids = array();
          $file_count = count($files['name']);
          $has_files = false; // Flag to track if any files are uploaded

          for ($i = 0; $i < $file_count; $i++) {
            // Prepare file data for upload
            $file = array(
              'name' => $files['name'][$i],
              'type' => $files['type'][$i],
              'tmp_name' => $files['tmp_name'][$i],
              'error' => $files['error'][$i],
              'size' => $files['size'][$i],
            );

           // Handle the upload
            $uploaded_file = wp_handle_upload($file, array('test_form' => false));
            if (isset($uploaded_file['file'])) {
              $file_name = uniqid() . '-' . basename($uploaded_file['file']);
              $attachment = array(
                'guid' => $uploaded_file['url'],
                'post_mime_type' => $uploaded_file['type'],
                'post_title' => preg_replace('/\.[^.]+$/', '', $file_name),
                'post_content' => '',
                'post_status' => 'inherit'
              );
              $attachment_id = wp_insert_attachment($attachment, $uploaded_file['file']);
              if (!is_wp_error($attachment_id)) {
                require_once(ABSPATH . 'wp-admin/includes/image.php');
                $attachment_data = wp_generate_attachment_metadata($attachment_id, $uploaded_file['file']);
                wp_update_attachment_metadata($attachment_id, $attachment_data);
                $uploaded_file_ids[] = $attachment_id;
                $has_files = true; // Mark that files were uploaded
              }
            }
          }

           // Handle gallery images
          if ($has_files) {
            $total_gallery_images = count($uploaded_file_ids);
            if ($total_gallery_images <= 10) {
              update_post_meta($post_id, 'gallery', $uploaded_file_ids);
            } else {
              return new \WP_Error('gallery_limit_exceeded', 'Gallery image limit exceeded (max: 10)');
            }
          } else {
           // If no files were uploaded, delete existing gallery images
            delete_post_meta($post_id, 'gallery');
          }
        }
        if(empty($_FILES['gallery']))
        {
          delete_post_meta($post_id, 'gallery');
        }
    //  if (!empty($uploaded_file_ids)) {
    //     // $existing_gallery_ids_string = get_post_meta($post_id, 'gallery', true);
  
    //     // $existing_gallery_ids = !empty($existing_gallery_ids_string) ? explode(',', $existing_gallery_ids_string) : array();
    
    //     $total_gallery_images = count($uploaded_file_ids);
    //     if ($total_gallery_images <= 10) {
    //         // $merged_gallery_ids = array_slice(array_merge($existing_gallery_ids, $uploaded_file_ids), 0, 10);
    //         // update_post_meta($post_id, 'gallery', implode(',', $merged_gallery_ids));
    //         update_post_meta($post_id, 'gallery',$uploaded_file_ids);
    //      } else {
    //         return new \WP_Error('gallery_limit_exceeded', 'Gallery image limit exceeded (max: 10)', array('status' => 400));
    //     }
    // }
      if (!empty($country)) {
      $country = get_term_by('name',$country, 'city');
      if (!$country->term_id) {
         wp_insert_term($country, 'city');
      }
       wp_set_post_terms($post_id, $country->term_id, 'city', true);
     }

    if (!empty($city)) {
      $city =  get_term_by('name',$city, 'city');
      if (!$city->term_id) {
          wp_insert_term($city, 'city');
      }
       wp_set_post_terms($post_id, $city->term_id, 'city', true);
     }

     return new \WP_REST_Response(array(
         'id' => $post_id,
         'message' => 'Profile created successfully'
     ), 200);
  }
  private function upload_file($file)
  {
    $upload_dir = wp_upload_dir();
    $file_name = uniqid() . '-' .basename($file['name']);
    $file_path = $upload_dir['path'] . '/' . $file_name;

    if (move_uploaded_file($file['tmp_name'], $file_path)) {
        $attachment = array(
            'post_title' => $file_name,
            'post_content' => '',
            'post_status' => 'inherit',
            'post_mime_type' => $file['type']
        );

        $attachment_id = wp_insert_attachment($attachment, $file_path);
        if (!is_wp_error($attachment_id)) {
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $attachment_data = wp_generate_attachment_metadata($attachment_id, $file_path);
            wp_update_attachment_metadata($attachment_id, $attachment_data);
            return $attachment_id;
        }
    }
  }
}
$createprofile =new createprofile();

class usersdetails
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'users'));
  }

  function users()
  {
    register_rest_route(
      'Voxel/v1',
      '/usersdetails/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get'),
      )
    );
  }

  function get($request) {
    $user_id = $request->get_param('id');
    $user = get_userdata($user_id);
    $per_page = $request->get_param('per_page') ? intval($request->get_param('per_page')) : 5;
    $page = $request->get_param('page') ? intval($request->get_param('page')) : 1;

    // Calculate offset based on pagination parameters
    $offset = ($page - 1) * $per_page;
    // $users = get_users(array(
    // 'number' => $per_page,
    // 'offset' => $offset,));
    if (!$user) {
        return new \WP_Error('user_not_found', 'User not found', array('status' => 404));
    }

    // Get user posts of type 'places'
    $user_posts = get_posts(array(
        'author' => $user_id,
        'post_status' => 'publish',
        'post_type' => 'places',
        'numberposts' => -1,
    ));

    // Get user profiles
    $profiles = get_posts(array(
        'author' => $user_id,
        'post_status' => 'publish',
        'post_type' => 'profile',
        'numberposts' => -1,
    ));

    $posts_data = array();
    $profile_data = array();

     global $wpdb;
$query = "
    SELECT DISTINCT
        t.*,
        r.id AS reply_id,
        r.user_id AS reply_user_id,
        r.parent_id AS reply_parent_id,
        r.content AS reply_content,
        r.details AS reply_details,
        r.created_at AS reply_created_at,
        r.edited_at AS reply_edited_at,
        l.user_id AS like_user_id,
        l.status_id AS like_status_id,
        rl.user_id AS reply_like_user_id,
        rl.reply_id AS reply_like_reply_id
    FROM
        {$wpdb->prefix}voxel_timeline t
    LEFT JOIN {$wpdb->prefix}voxel_timeline_replies r ON t.id = r.status_id
    LEFT JOIN {$wpdb->prefix}voxel_timeline_likes l ON t.id = l.status_id
    LEFT JOIN {$wpdb->prefix}voxel_timeline_reply_likes rl ON r.id = rl.reply_id
    WHERE
        t.user_id = %d
    ORDER BY
        t.created_at DESC, r.created_at ASC
";
$timeline_data = $wpdb->get_results($wpdb->prepare($query, $user_id));

$timeline_entries = array();
$replies_added = array(); // Track replies added to prevent duplicates

foreach ($timeline_data as $entry) {
    // Process statuses
    if (!isset($timeline_entries[$entry->id])) {
        $user_info = get_userdata($entry->user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $details = !empty($entry->details) ? json_decode($entry->details, true) : array();
        $attachment_urls = array();
        if (isset($details['files'])) {
            $file_ids = explode(',', $details['files']);
            foreach ($file_ids as $file_id) {
                $file_url = wp_get_attachment_url($file_id);
                if ($file_url) {
                    $attachment_urls[] = $file_url;
                }
            }
        }

        // Process review score adjustments
        $meta_review_array = isset($details['rating']) ? isset($details['rating']): array();
        // print_r($details['rating']['score']);
        // die();
        $review_score_adjusted = array(
            'overall' => isset($details['rating']['score']) ? $details['rating']['score'] + 3 : null,
            'service' => isset($details['rating']['custom-660']) ? $details['rating']['custom-660'] + 3 : null,
            'hospitality' => isset($details['rating']['custom-978']) ? $details['rating']['custom-978'] + 3 : null,
            'pricing' => isset($details['rating']['custom-271']) ? $details['rating']['custom-271'] + 3 : null
        );
        $timeline_entries[$entry->id] = array(
            'id' => $entry->id,
            'user_id' => $entry->user_id,
            'profile_pic' => get_avatar_url($entry->user_id),
            'user_name' => $user_name,
            'published_as' => $entry->published_as,
            'post_id' => $entry->post_id,
            'content' => $entry->content,
            'details' => $attachment_urls,
            'review_score_adjusted' => $review_score_adjusted,
            'review_score' => isset($entry->review_score) ?isset($entry->review_score) +3 : null,
            'created_at' => $entry->created_at,
            'edited_at' => $entry->edited_at,
            'replies' => array(),
            'likes' => array(),
            'reply_likes' => array(),
            'like_count' => 0,
        );
    }

    // Process likes
    if ($entry->like_user_id && !isset($timeline_entries[$entry->id]['likes'][$entry->like_user_id])) {
        $user_info = get_userdata($entry->like_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['likes'][$entry->like_user_id] = array(
            'like_user_id' => $entry->like_user_id,
            'like_user_name' => $user_name,
            'like_status_id' => $entry->like_status_id
        );
        $timeline_entries[$entry->id]['like_count']++;
    }

    // Process replies
    if ($entry->reply_id && !isset($replies_added[$entry->reply_id])) {
        $user_info = get_userdata($entry->reply_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $reply_details = !empty($entry->reply_details) ? json_decode($entry->reply_details, true) : array();
        $reply_to = isset($reply_details['reply_to']) ? $reply_details['reply_to'] : null;

        $reply_data = array(
            'reply_id' => $entry->reply_id,
            'reply_parent_id' => $entry->reply_parent_id,
            'reply_user_id' => $entry->reply_user_id,
            'reply_user_name' => $user_name,
            'reply_profile_pic' => get_avatar_url($entry->reply_user_id),
            'reply_content' => $entry->reply_content,
            'reply_details' => $reply_details,
            'reply_created_at' => $entry->reply_created_at,
            'reply_edited_at' => $entry->reply_edited_at,
            'reply_likes_count' => 0,
            'replies' => array()
        );
        $replies_added[$entry->reply_id] = $reply_data;

        if ($reply_to && isset($timeline_entries[$entry->id]['replies'][$reply_to])) {
            $timeline_entries[$entry->id]['replies'][$reply_to]['replies'][] = $reply_data;
        } elseif ($entry->reply_parent_id && isset($timeline_entries[$entry->reply_parent_id]['replies'])) {
            $timeline_entries[$entry->reply_parent_id]['replies'][] = $reply_data;
        } else {
            $timeline_entries[$entry->id]['replies'][] = $reply_data;
        }
    }

    // Process reply likes
    if ($entry->reply_like_user_id && !isset($timeline_entries[$entry->id]['reply_likes'][$entry->reply_like_user_id])) {
        $user_info = get_userdata($entry->reply_like_user_id);
        $user_name = $user_info ? $user_info->display_name : 'Unknown';
        $timeline_entries[$entry->id]['reply_likes'][$entry->reply_like_user_id] = array(
            'reply_like_user_id' => $entry->reply_like_user_id,
            'reply_like_user_name' => $user_name,
            'reply_like_reply_id' => $entry->reply_like_reply_id
        );

        // Find the reply to which this like belongs and increment its like count
        foreach ($timeline_entries[$entry->id]['replies'] as &$reply) {
            if ($reply['reply_id'] == $entry->reply_like_reply_id) {
                $reply['reply_likes_count']++;
                break;
            }
        }
    }
}

// Convert associative arrays to indexed arrays
foreach ($timeline_entries as &$timeline_entry) {
    $timeline_entry['likes'] = array_values($timeline_entry['likes']);
    $timeline_entry['replies'] = array_values($timeline_entry['replies']);
    $timeline_entry['reply_likes'] = array_values($timeline_entry['reply_likes']);
}
$indexed_timeline_entries = array_values($timeline_entries);

    foreach ($profiles as $profile) {
        $post_thumbnail_id = get_post_thumbnail_id($profile->ID);
        $post_thumbnail_url = $post_thumbnail_id ? wp_get_attachment_url($post_thumbnail_id) : '';

        $gallery_images_ids = get_post_meta($profile->ID, 'gallery', true);

         // Ensure $gallery_images_ids is a string before using explode
        if (is_string($gallery_images_ids)) {
          $gallery_images_ids_array = explode(',', $gallery_images_ids);
        } else {
         // Handle cases where $gallery_images_ids is not a string
          $gallery_images_ids_array = array();
        }
        // Initialize array for gallery image URLs
        $gallery_images_urls = array();

        foreach ($gallery_images_ids_array as $image_id) {
          $image_url = wp_get_attachment_url($image_id);
          if ($image_url) {
            $gallery_images_urls[] = $image_url;
          }
        }
        
        // Get location data from post meta
        $location_data = get_post_meta($profile->ID, 'location', true);
        $height=get_post_meta($profile->ID, 'height', true);
        $weight=get_post_meta($profile->ID, 'weight', true);
        $location_data_decoded = !empty($location_data) ? json_decode($location_data, true) : array();
        $city_terms = wp_get_post_terms($profile->ID, 'city', array('fields' => 'names')); 
        $location_data_decoded['city'] = $city_terms ? $city_terms :'unknow';
        $profile_data[] = array(
            'ID' => $profile->ID,
            'post_title' => $profile->post_title,
            'post_content' => $profile->post_content,
            'post_date' => $profile->post_date,
            'post_type' => $profile->post_type,
            'height'=>$height,
            'weight'=>$weight,
            'post_thumbnail_url' => $post_thumbnail_url,
            'gallery_images' => $gallery_images_urls,
            'location_data' =>$location_data_decoded 
        );
    }

    foreach ($user_posts as $post) {
        $posts_data[] = array(
            'ID' => $post->ID,
            'post_title' => $post->post_title,
            'post_content' => $post->post_content,
            'post_date' => $post->post_date,
        );
    }
   $post_count_query = $wpdb->prepare("
            SELECT COUNT(*) AS post_count
            FROM {$wpdb->prefix}voxel_timeline
            WHERE user_id = %d
        ", $user_id);
    $post_count = $wpdb->get_var($post_count_query);
    // Get user meta data
    $user_meta = get_user_meta($user_id);
    $profile_pic_url = get_avatar_url($user_id);
    $user_meta_cleaned = array();
    foreach ($user_meta as $key => $value) {
        $user_meta_cleaned[$key] = is_array($value) ? $value[0] : $value;
    }
    $follow_stats = isset($user_meta_cleaned['voxel:follow_stats']) ? json_decode($user_meta_cleaned['voxel:follow_stats'], true) : array('following' => array(), 'followed' => array());
    $notifications_meta = isset($user_meta_cleaned['voxel:notifications']) ? json_decode($user_meta_cleaned['voxel:notifications'], true) : array('unread' => 0, 'since' => '');
     $follow_stats['post_count'] = $post_count ?? 0;

    $user_data = array(
        'id' => $user->ID,
        'name' => $user->display_name,
        'follow_stats' => $follow_stats,
        'notifications_meta' => $notifications_meta,
        'email' => $user->user_email,
        'meta' => $user_meta_cleaned,
        'avatar' => $profile_pic_url,
        'profile_data' => $profile_data,
        'share'  =>get_author_posts_url($user->ID),
        'timeline_entries' => $indexed_timeline_entries
        // 'posts_data' => $posts_data
    );

    return $user_data;
}

function hasLike($likes, $user_id)
  {
    foreach ($likes as $like) {
      if ($like['like_user_id'] == $user_id) {
        return true;
      }
    }
    return false;
  }
  function hasLikea($likes, $user_id)
  {
    foreach ($likes as $like) {
      if ($like['reply_like_user_id'] == $user_id) {
        return true;
      }
    }
    return false;
  }

}

$users = new usersdetails();

class userprofilepost
{
 function __construct()
  {
    add_action('rest_api_init', array($this, 'userprofilepost'));
  }

  function userprofilepost()
  {
    register_rest_route(
      'Voxel/v1',
      '/userprofilepost',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'insert_profile'),
      )
    );
  }
  function insert_profile($request){
    global $wpdb;
    
    $user_id = $request->get_param('user_id');
    $content = $request->get_param('content');
    // $review_score = $request->get_param('review_score')  ?? '';

    
    // Validate required fields
    if (!$user_id ) {
        return new \WP_Error('missing_required_fields', 'Missing required fields', array('status' => 400));
    }
    $user = get_user_by('id', $user_id);
    if (!$user) {
        return new \WP_Error('user_not_found', 'User not found.', array('status' => 404));
    }
     // Query for the post ID based on the author ID and post type
     $args = array(
      'author' => $user_id,
      'post_type' => 'profile',
      'post_status' => 'publish',
      'posts_per_page' => 1,
  );

  $posts = get_posts($args);

  if (empty($posts)) {
      return new \WP_Error('post_not_found', 'Post not found.', array('status' => 404));
  }

  $post_id = $posts[0]->ID;
    // Handle file uploads
    $files = $request->get_file_params('gallery');
    
    $uploaded_file_ids = array();
    if (!empty($files['gallery']) ) {
      $file_count = count($files['gallery']['name']);
      for ($i = 0; $i < $file_count; $i++) {
          $file = array(
              'name' => $files['gallery']['name'][$i],
              'type' => $files['gallery']['type'][$i],
              'tmp_name' => $files['gallery']['tmp_name'][$i],
              'error' => $files['gallery']['error'][$i],
              'size' => $files['gallery']['size'][$i],
          );

          $uploaded_file = wp_handle_upload($file, array('test_form' => false));
          if (isset($uploaded_file['file'])) {
              $file_name = uniqid().'-'.basename($uploaded_file['file']);
              $attachment = array(
                  'guid' => $uploaded_file['url'],
                  'post_mime_type' => $uploaded_file['type'],
                  'post_title' => preg_replace('/\.[^.]+$/', '', $file_name),
                  'post_content' => '',
                  'post_status' => 'inherit'
              );
              $attachment_id = wp_insert_attachment($attachment, $uploaded_file['file']);
              if (!is_wp_error($attachment_id)) {
                  require_once(ABSPATH . 'wp-admin/includes/image.php');
                  $attachment_data = wp_generate_attachment_metadata($attachment_id, $uploaded_file['file']);
                  wp_update_attachment_metadata($attachment_id, $attachment_data);
                  $uploaded_file_ids[] = $attachment_id;
              }
          }
      }
    }
   
    $details = !empty($uploaded_file_ids) ? json_encode(array('files' => implode(',', $uploaded_file_ids))) : $request->get_param('details');

    // Prepare the data
    $data = array(
      'user_id' => $user_id,
      'post_id' => $post_id,
      'content' => $content,
      'details' => $details,
      'review_score' => null
  );
  
  // Insert the data into the database
  $inserted = $wpdb->insert(
      $wpdb->prefix . 'voxel_timeline',
      $data,
      array('%d', '%d', '%s', '%s', '%f')
  );
    if ($inserted === false) {
        return new \WP_Error('db_insert_error', 'Database insert error');
    }

    return new \WP_REST_Response(array('success' => true, 'inserted_id' => $wpdb->insert_id));
  }
}
$userprofilepost = new userprofilepost();


class deleteprofilepost
{
 function __construct()
  {
    add_action('rest_api_init', array($this, 'deleteprofilepost'));
  }

  function deleteprofilepost()
  {
    register_rest_route(
      'Voxel/v1',
      '/deleteprofilepost',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'delete_profile'),
      )
    );
  }
  function delete_profile($request) {
    global $wpdb;
    
    $timeline_id = intval($request['id']); // Get the ID from the request

    // Prepare the delete query
    $delete_query = "
        DELETE FROM wp_voxel_timeline
        WHERE id = %d
    ";

    // Execute the delete query
    $deleted = $wpdb->query($wpdb->prepare($delete_query, $timeline_id));

    if ($deleted) {
        return new \WP_REST_Response(array(
            'message' => "Record with ID $timeline_id has been successfully deleted.",
            'deleted' => true
        ));
    } else {
        return new \WP_REST_Response(array(
            'message' => "Failed to delete record with ID $timeline_id. Please check if the ID exists.",
            'deleted' => false
        ));
    }
   }
}
$deleteprofilepost = new deleteprofilepost();

class Anylatics {
  function __construct() {
      add_action('rest_api_init', array($this, 'anylatics'));
  }

  function anylatics() {
      register_rest_route(
          'Voxel/v1',
          '/anylatics/(?P<id>\d+)',
          array(
              'methods' => 'GET',
              'callback' => array($this, 'details'),
          )
      );
  }

  function details($request) {
      $user_id = $request->get_param('id'); // Use get_param for single parameter

      // Retrieve user meta
      $user_meta = get_user_meta($user_id);
      if (!is_array($user_meta)) {
          return new \WP_Error('no_user', 'Invalid user ID', array('status' => 404));
      }

      $user_meta_cleaned = array();
      foreach ($user_meta as $key => $value) {
          $user_meta_cleaned[$key] = is_array($value) ? $value[0] : $value;
      }

      $post_stats = isset($user_meta_cleaned['voxel:post_stats']) ? json_decode($user_meta_cleaned['voxel:post_stats'], true) : array();

      // Extract collection, events, and places with default values if not set
      $collection_stats = isset($post_stats['collection']) ? $post_stats['collection'] : array('publish' => 0);
      $events_stats = isset($post_stats['events']) ? $post_stats['events'] : array('publish' => 0);
      $places_stats = isset($post_stats['places']) ? $post_stats['places'] : array('publish' => 0);

      $user_data = array(
          'collection_stats' => $collection_stats,
          'places_stats' => $places_stats,
          'events_stats' => $events_stats
      );

      return $user_data;
  }
}

$anylatics = new Anylatics();

class Palcebyuser
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'Palcebyuser'));
  }
  function Palcebyuser()
  {
    register_rest_route(
      'Voxel/v1',
      '/Palcebyuser/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
   
    $post_author= $request->get_param('id');
 
    $query_args = array(
      'author' => $post_author,
      'post_type' => 'places',
      'post_status' => 'publish',
      'posts_per_page' => -1,
    );

    // Fetch the posts
    $posts = get_posts($query_args);

    if (empty($posts)) {
      return new \WP_REST_Response(array('message' => 'no_posts_found'));
    }
    $formatted_posts = array();

    foreach ($posts  as $posts) {
      $featured_image_id = get_post_thumbnail_id($posts->ID);
      $featured_image_url = '';
      if ($featured_image_id) {
        $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
        if (is_array($featured_image_data)) {
          $featured_image_url = $featured_image_data[0];
        }
      }

      $profile_logo_id = get_post_meta($posts->ID, 'logo', true);
      $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';
      $address = get_post_meta($posts->ID, 'location', true);
      $address_data = json_decode($address, true);
      $review_stats_json = get_post_meta($posts->ID, 'voxel:review_stats', true);
      if ($review_stats_json) {
        $review_stats = json_decode($review_stats_json, true); // Decode the JSON to an associative array

        $total_reviews = $review_stats['total'] ?? 0; // Using null coalescing operator to provide default value
        $average_rating = isset($review_stats['average'])  ? round($review_stats['average'] + 3, 2) : ''; // Defaulting to '0' if not set
      }
      // Extract the desired components
      $address = isset($address_data['address']) ? $address_data['address'] : '';
      $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
      $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';
      $opening_hours_data = get_post_meta($posts->ID, 'work-hours', true);
      $opening_hours = json_decode($opening_hours_data, true);
  
      $formatted_opening_hours = array();
      if (!empty($opening_hours) && is_array($opening_hours)) {
        foreach ($opening_hours as $hours_data) {
          $days = $hours_data['days'] ?? array();
          $status = $hours_data['status'] ?? 'hours';
          $hours = $hours_data['hours'] ?? array();
          foreach ($days as $day) {
            if (!isset($formatted_opening_hours[$day])) {
              $formatted_opening_hours[$day] = array();
            }
            if ($status === 'closed') {
              $formatted_opening_hours[$day][] = 'Closed all day';
            } elseif ($status === 'appointments_only') {
              $formatted_opening_hours[$day][] = 'Appointments Only';
            }elseif (!empty($hours)) {
              foreach ($hours as $hour) {
                $formatted_opening_hours[$day][] = $hour['from'] . '-' . $hour['to'];
              }
            } else {
              // If no hours are provided, indicate that it's open all day
              $formatted_opening_hours[$day][] = 'Open all day';
            }
          }
        }
      }
      $formatted_posts[] = array(
        'id' => $posts->ID,
        'name' => $posts->post_title,
        'content' => $posts->post_content,
        'featured_image_url' => $featured_image_url,
        'profile_logo_url' => $profile_logo_url,
        'address' => $address,
        'latitude' => $latitude,
        'longitude' => $longitude,
        'Total Reviews' => $total_reviews,
        'Average Rating' =>  $average_rating,
        'opening_hours' => $formatted_opening_hours,

      );
    }
    return $formatted_posts;
  }
}
$Palcebyuser = new Palcebyuser();

class Eventbyuser
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'Eventbyuser'));
  }
  function Eventbyuser()
  {
    register_rest_route(
      'Voxel/v1',
      '/Eventbyuser/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request)
  {
    $post_author= $request->get_param('id'); 
    
    $query_args = array(
      'author' => $post_author,
      'post_type' => 'events',
      'post_status' => 'publish',
      'posts_per_page' => -1,
    );
    $events = get_posts($query_args);
    if (empty($events)) {
      return new \WP_REST_Response(array('message' => 'no_events_found'));
    }

    $formatted_posts = array();

    foreach ($events  as $events) {
      $featured_image_id = get_post_thumbnail_id($events->ID);
      $featured_image_url = '';
      if ($featured_image_id) {
        $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
        if (is_array($featured_image_data)) {
          $featured_image_url = $featured_image_data[0];
        }
      }
      $event_date = get_post_meta($events->ID, 'event_date', true);
      $profile_logo_id = get_post_meta($events->ID, 'logo', true);
      $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';
      $address = get_post_meta($events->ID, 'location', true);
      $address_data = json_decode($address, true);
      // Extract the desired components
      $address = isset($address_data['address']) ? $address_data['address'] : '';
      $latitude = isset($address_data['latitude']) ? $address_data['latitude'] : '';
      $longitude = isset($address_data['longitude']) ? $address_data['longitude'] : '';
      $formatted_posts[] = array(
        'id' => $events->ID,
        'name' => $events->post_title,
        'content' => $events->post_content,
        'featured_image_url' => $featured_image_url,
        'profile_logo_url' => $profile_logo_url,
        'address' => $address,
        'latitude' => $latitude,
        'longitude' => $longitude,
        'event_date' => $event_date,

      );
    }
    return $formatted_posts;
  }
}
$Eventbyuser =new Eventbyuser();

class getuseroders
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'getuseroders'));
  }
  function getuseroders()
  {
    register_rest_route(
      'Voxel/v1',
      '/getuseroders/(?P<order_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request) {
     global $wpdb;

    // Retrieve order ID from URL parameters
    $order_id = $request->get_param('order_id');

    // Prepare SQL query to fetch order details for the given order ID
    $query = $wpdb->prepare("
        SELECT *
        FROM {$wpdb->prefix}voxel_orders
        WHERE id = %d
    ", $order_id);

    $result = $wpdb->get_row($query, ARRAY_A);

    if ($result) {
      // Decode JSON fields if needed
      $details = json_decode($result['details'], true);
      $object_details = json_decode($result['object_details'], true);
      // Fetch file details if file ID is present in details
      $file_id = isset($details['fields']['file']) ? intval($details['fields']['file']) : 0;
      $file_url = $file_id ? wp_get_attachment_url($file_id) : '';
      $file_post = $file_id ? get_post($file_id) : null;
      $file_name = $file_post ? $file_post->post_title : '';
       // Add file details inside the 'fields' array
      if (isset($details['fields'])) {
        $details['fields']['file_name'] = $file_name;
        $details['fields']['file_url'] = $file_url;
      }
      $customer_id = $result['customer_id'];
      $customer_info = get_userdata($customer_id);
      $customer_name = $customer_info ? $customer_info->display_name : '';
      $customer_profile_pic_url = get_avatar_url($customer_id);
      $post_name = get_the_title($result['post_id']);
      // Prepare detailed order data for response
      $formatted_order = array(
        'order_id' => $result['id'],
        'post_id' => $result['post_id'],
        'post_name' => $post_name,
        'product_type' => $result['product_type'],
        'product_key' => $result['product_key'],
        'customer_id' => $result['customer_id'],
        'vendor_id' => $result['vendor_id'],
         'username' => $customer_name,
        'profile_pic_url' => $customer_profile_pic_url,
        'details' => $details,
        'status' => $result['status'],
        'session_id' => $result['session_id'],
        'mode' => $result['mode'],
        'object_id' => $result['object_id'],
        'object_details' => $object_details,
        'testmode' => $result['testmode'],
        'catalog_mode' => $result['catalog_mode'],
        'created_at' => $result['created_at'],
        'checkin' => $result['checkin'],
        'checkout' => $result['checkout'],
        'timeslot' => $result['timeslot'],
      );

      return rest_ensure_response($formatted_order);
    } else {
      return rest_ensure_response(array(
        'message' => 'Order not found',
      ));
    }
}
}
$getuseroders= new getuseroders();

class GetOrderBasicInfo
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes()
  {
    register_rest_route(
      'Voxel/v1',
      '/order-basic-info/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get_order_basic_info'),
      )
    );
  }

  function get_order_basic_info($request) {
    global $wpdb;

    // Retrieve customer ID from query parameters
    $customer_id = $request->get_param('id');
    $profile_pic_url =get_avatar_url($customer_id);

    // Prepare SQL query to fetch basic order info for the given customer ID
   $query = $wpdb->prepare("
        SELECT *
        FROM {$wpdb->prefix}voxel_orders
        WHERE customer_id = %d
    ", $customer_id);


    $results = $wpdb->get_results($query, ARRAY_A);

    if ($results) {
      // Format response
      $formatted_orders = array();
      foreach ($results as $result) {
        $post_name = get_the_title($result['post_id']);
        $user_info = get_userdata($customer_id); // Get user info
        $username = $user_info ? $user_info->user_login : 'Unknown';
        $details = json_decode($result['details'], true);
        $formatted_orders[] = array(
          'order_id' => $result['id'],
          'post_id' => $result['post_id'],
          'pricing' => $details['pricing'],
          'status' => $result['status'],
          'post_name' => $post_name,
          'created_at' => $result['created_at'],
        );
      }

      return rest_ensure_response(array(
        'order_count' => count($formatted_orders),
        'username' => $username,
        'profile_pic_url' =>$profile_pic_url,
        'orders' => $formatted_orders,
      ));
    } else {
      return rest_ensure_response(array(
        'order_count' => 0,
        'orders' => array(),
      ));
    }
  }
}

$GetOrderBasicInfo = new GetOrderBasicInfo();

class GetOrderStatusNotes
{
    // Define status messages
    private $status_messages = array(
        'author.refund_approved' => 'Refund request approved by vendor.',
        'customer.refund_requested' => 'Customer requested a refund.',
        'author.approved' => 'Order has been approved',
        'customer.canceled' => 'Order canceled by customer.',
        'customer.refund_request_canceled' => 'Customer canceled their refund request.',
        'author.refund_declined'=> 'Refund request declined by vendor.',
        'author.declined'=> 'Order has been declined.',
        'customer.payment_authorized'=>'Funds have been authorized and the order is awaiting approval by the vendor.',
        'customer.checkout_canceled' =>'Checkout canceled by user.',
        // Add other statuses as needed
    );

    function __construct()
    {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    function register_routes()
    {
        register_rest_route(
            'Voxel/v1',
            '/order-status-notes/(?P<order_id>\d+)',
            array(
                'methods' => 'GET',
                'callback' => array($this, 'get_order_status_notes'),
            )
        );
    }

    function get_order_status_notes($request)
    {
        global $wpdb;

        // Retrieve order ID from URL parameters
        $order_id = $request->get_param('order_id');

        // Prepare SQL query to fetch status notes for the given order ID
        $query = $wpdb->prepare("
            SELECT *
            FROM {$wpdb->prefix}voxel_order_notes
            WHERE order_id = %d
            ORDER BY created_at ASC
        ", $order_id);

        $results = $wpdb->get_results($query, ARRAY_A);

        if ($results) {
            // Format response
            $formatted_notes = array();
            foreach ($results as $result) {
                // Decode JSON safely
                $details = !empty($result['details']) ? json_decode($result['details'], true) : null;

                // Convert type to human-readable message
                $type_message = $this->convert_type($result['type']);
                
                $formatted_notes[] = array(
                    'id' => $result['id'],
                    'type' => $type_message,
                    'details' => $details,
                    'created_at' => $result['created_at'],
                );
            }

            return rest_ensure_response(array(
                'order_id' => $order_id,
                'notes' => $formatted_notes,
            ));
        } else {
            return rest_ensure_response(array(
                'message' => 'No notes found for the given order ID',
            ));
        }
    }

    // Convert type to human-readable message
    private function convert_type($type)
    {
        return isset($this->status_messages[$type]) ? $this->status_messages[$type] : 'Unknown status';
    }
}

$getOrderStatusNotes = new GetOrderStatusNotes();

class UpdateOrderStatus
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes()
  {
    register_rest_route(
      'voxel/v1',
      '/update-order-status/(?P<order_id>\d+)',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'update_order_status'),
      )
    );
  }

  // function permissions_check($request)
  // {
  //   return current_user_can('edit_posts');
  // }

  function update_order_status($request)
  {
    global $wpdb;

    $order_id = $request->get_param('order_id');
    $status = sanitize_text_field($request->get_param('status'));

    $table_name = $wpdb->prefix . 'voxel_orders';

    // Update the status in the database
    $updated = $wpdb->update(
      $table_name,
      array('status' => $status),
      array('id' => $order_id),
      array('%s'),
      array('%d')
    );

    if ($updated !== false) {
      // Insert a note into wp_voxel_order_notes
      $note_data = array(
        'order_id' => $order_id,
        'type' => 'order.status.updated',
        'details' => json_encode(array('status' => $status)),
                'created_at' => current_time('mysql', 1), // Current time in GMT
              );

      $note_inserted = $wpdb->insert(
        $wpdb->prefix . 'voxel_order_notes',
        $note_data,
        array('%d', '%s', '%s', '%s')
      );

      if ($note_inserted !== false) {
        return rest_ensure_response(array(
          'message' => 'Order status updated and note added successfully',
          'order_id' => $order_id,
          'status' => $status,
        ));
      } else {
        return new WP_Error('db_insert_error', 'Order status updated, but failed to insert note', array('status' => 500));
      }
    } else {
      return new WP_Error('db_update_error', 'Failed to update order status', array('status' => 500));
    }
  }
}

$updateOrderStatus = new UpdateOrderStatus();




class Claim {
  function __construct()
  {
    add_action('rest_api_init', array($this, 'Claim'));
  }
  function Claim()
  {
    register_rest_route(
      'Voxel/v1',
      '/claim',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'postclaim'),
      )
    );
  }
  function postclaim($request){
    $full_name = sanitize_text_field($request->get_param('full_name'));
    $phone = sanitize_text_field($request->get_param('phone'));
    $post_id = $request->get_param('post_id');
    $user_id = $request->get_param('customer_id');
    $file = isset($_FILES['proof_of_ownership']) ? $_FILES['proof_of_ownership'] : null;
    // error_log('Full Name: ' . $full_name);
    // error_log('Phone: ' . $phone);
    // error_log('Post ID: ' . $post_id);
    // error_log('Customer ID: ' . $user_id);
    // error_log('File: ' . print_r($file, true));
    // Check for required fields
    if (empty($full_name) || empty($phone) || empty($file) || empty($post_id) || empty($user_id)) {
        return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

  // Handle file upload
  $post = get_post($post_id);
  if($post){
     $vendor_id = $post->post_author;
   }else{
    return new \WP_REST_Response(array('message'=>'post not found'));
   }
   
   $uploaded_file = wp_handle_upload($file, array('test_form' => false));
   if (isset($uploaded_file['error'])) {
       return new \WP_REST_Response('upload_error', $uploaded_file['error']);
   }

   $attachment_id = null;
   if (isset($uploaded_file['file'])) {
       $file_name = uniqid().basename($uploaded_file['file']);
       $attachment = array(
           'guid' => $uploaded_file['url'],
           'post_mime_type' => $uploaded_file['type'],
           'post_title' => preg_replace('/\.[^.]+$/', '', $file_name),
           'post_content' => '',
           'post_status' => 'inherit'
       );
       $attachment_id = wp_insert_attachment($attachment, $uploaded_file['file']);
       if (!is_wp_error($attachment_id)) {
           require_once(ABSPATH . 'wp-admin/includes/image.php');
           $attachment_data = wp_generate_attachment_metadata($attachment_id, $uploaded_file['file']);
           wp_update_attachment_metadata($attachment_id, $attachment_data);
       } else {
           return new \WP_REST_Response('attachment_error', 'Failed to create attachment');
       }
   } else {
       return new \WP_REST_Response('upload_error', 'File upload failed');
   }

    // Insert order into the database
    global $wpdb;
    $order_id = $wpdb->insert(
        'wp_voxel_orders',
        array(
            'post_id' => $post_id,
            'product_type' => 'claim',
            'product_key' => 'product-3',
            'customer_id' => $user_id, // Replace with actual customer ID
            'vendor_id' => $vendor_id, // Replace with actual vendor ID
            'details' => json_encode(array(
                'fields' => array(
                    'text' => $full_name,
                    'phone' => $phone,
                    'file' => $attachment_id
                ),
                'pricing' => array(
                    'base_price' => 25,
                    'total' => 25,
                    'currency' => 'USD'
                ),
                'checkout' => array(
                    'currency' => 'usd',
                    'amount_subtotal' => 2500,
                    'amount_total' => 2500
                )
            )),
            'status' => 'pending_payment',
            'session_id' => '',
            'mode' => 'payment',
            'testmode' => 1,
            'catalog_mode' => 0,
            'created_at' => current_time('mysql')
        )
    );

    if ($order_id === false) {
        return new \WP_REST_Response('db_insert_error', 'Failed to insert order');
    }

    return rest_ensure_response(array('order_id' => $wpdb->insert_id));
  }
}
$Claim =new Claim();

class checkout
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'checkout'));
  }
  function checkout()
  {
    register_rest_route(
      'Voxel/v1',
      '/checkout',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'getcheckout'),
      )
    );
  }

function getcheckout($request) {
  require_once get_template_directory() . '/app/stripe/library/init.php';
  global $wpdb;
  \Stripe\Stripe::setApiKey('sk_test_eq6VG6B6hEf51jXh8N6iSS4n00N0qMyLpd');

  $order_id = sanitize_text_field($request->get_param('order_id'));
  $order_details = $this->get_order_details($order_id);
  if (!$order_details) {
      return new  \WP_REST_Response(array('message' =>'no_order', 'data'=>'Invalid Order ID'));
  }
  $order = $wpdb->get_row($wpdb->prepare("SELECT * FROM wp_voxel_orders WHERE id = %d", $order_id), ARRAY_A);
  if ($order) {
    $post_id = $order['post_id'];
    $details = isset($order['details']) ? json_decode($order['details'], true) : array();
    
  }
  $name= get_the_title($post_id); 
  $checkout_session = \Stripe\Checkout\Session::create([
      'payment_method_types' => ['card'],
      'line_items' => [[
          'price_data' => [
              'currency' => $order_details['checkout']['currency'],
              'product_data' => [
                  'name' =>  $name,
              ],
              'unit_amount' => $order_details['checkout']['amount_total'],
          ],
          'quantity' => 1,
      ]],
      'mode' => 'payment',
      'success_url' => site_url('/success?session_id={CHECKOUT_SESSION_ID}'),
      'cancel_url' => site_url('/cancel'),
  ]);

  $details['checkout'] = array(
    'id' => $checkout_session->id,
    'currency' => 'usd',
    'amount_subtotal' => 2500,
    'amount_total' => 2500,
    'total_details' => array(
        'amount_discount' => 0,
        'amount_shipping' => 0,
        'amount_tax' => 0
    )
);

$data = array(
  'details' => json_encode($details),
  'session_id' => $checkout_session->id,
);

// Where clause
$where = array(
  'id' => $order_id,
);

// Table name
$table = 'wp_voxel_orders';

// Execute the update query
$wpdb->update($table, $data, $where);

return rest_ensure_response(array('url' => $checkout_session->url));
}

function get_order_details($order_id) {
  global $wpdb;
  $order = $wpdb->get_row($wpdb->prepare("SELECT * FROM wp_voxel_orders WHERE id = %d", $order_id), ARRAY_A);
  // var_dump($order);die;
  return $order ? json_decode($order['details'], true) : null;
}

}
$checkout =new checkout();
// message for place and user
class Voxel_Messages {
  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/conversations/(?P<user_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get_user_conversations'),
        'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
  }

  function get_user_conversations($request) {
   global $wpdb;
$user_id = intval($request['user_id']);

// Initialize array to store conversations
$conversations = array();

// Function to get profile details based on type
function get_profile($id, $type) {
    if ($type === 'user') {
      $user_data = get_userdata($id);
         if ($user_data) { // Ensure $user_data is not false or null
          return array(
            'ID' => $id,
            'user_login' => $user_data->user_login,
            'user_nicename' => $user_data->user_nicename,
            'user_email' => $user_data->user_email,
            'user_url' => $user_data->user_url,
            'display_name' => $user_data->display_name,
            'nickname' => $user_data->nickname,
            'profile_pic' => get_avatar_url($id)
          );
        } else {
          return array('message' => 'User not found');
        }
    } elseif ($type === 'post') {
     $post = get_post($id);
        if ($post) { // Ensure $post is not false or null
          $profile_logo_id = get_post_meta($id, 'logo', true);
          $profile_logo_url = $profile_logo_id ? wp_get_attachment_url($profile_logo_id) : '';
          return array(
            'ID' => $id,
            'post_title' => $post->post_title,
            'post_url' => get_permalink($id),
            'post_thumbnail' => get_the_post_thumbnail_url($id, 'thumbnail'),
            'profile_logo_url' => $profile_logo_url
          );
        } else {
          return array('message' => 'Post not found');
        }
    }
    return array('message' => 'Profile not found');
}
// Function to process message details and get file URLs
function process_message_details($details_json) {
 $details = json_decode($details_json, true);
 if (isset($details['files'])) {
  $details = wp_get_attachment_url($details['files']);
  } else {
   $details= null;
  }
 return $details;
}
// Step 1: Fetch all places owned by the user
$places_query = "
    SELECT ID
    FROM wp_posts
    WHERE post_author = %d
      AND post_type = 'places'
      AND post_status = 'publish'
";
$owned_places = $wpdb->get_results($wpdb->prepare($places_query, $user_id));

// Initialize array to store place IDs
$place_ids = array_column($owned_places, 'ID');

// Step 2: Fetch conversations involving owned places
foreach ($place_ids as $place_id) {
    // Fetch messages involving this place
    $place_conversations_query = "
        SELECT *
        FROM wp_voxel_messages
        WHERE (sender_type = 'post' AND sender_id = %d)
           OR (receiver_type = 'post' AND receiver_id = %d)
        ORDER BY created_at DESC
    ";
    $place_conversations = $wpdb->get_results($wpdb->prepare($place_conversations_query, $place_id, $place_id));

    // Group messages by other participant
    $grouped_messages = array();
    foreach ($place_conversations as $message) {
        $sender_id = intval($message->sender_id);
        $receiver_id = intval($message->receiver_id);
        $other_id = ($sender_id == $place_id) ? $receiver_id : $sender_id;
        $other_type = ($sender_id == $place_id) ? $message->receiver_type : $message->sender_type;

        $profile = get_profile($other_id, $other_type);

        if (!isset($grouped_messages[$other_id])) {
            $grouped_messages[$other_id] = array(
                'user_id' => $other_id,
                'type' => $other_type,
                'profile' => $profile,
                'messages' => array()
            );
        }

        // Add place details if the place is the sender
        if ($sender_id == $place_id) {
            $place_profile = get_profile($place_id, 'post');
            $grouped_messages[$other_id]['place'] = array(
                'post_title' => $place_profile['post_title'],
                'post_type' => 'places',
                'profile_logo_url' => $place_profile['profile_logo_url'],
                'place_id' => $place_id
            );
        }
        // Check if receiver is a place
        elseif ($receiver_id == $place_id) {
          $place_profile = get_profile($place_id, 'post');
          $grouped_messages[$other_id]['place'] = array(
            'post_title' => $place_profile['post_title'],
            'post_type' => 'places',
            'profile_logo_url' => $place_profile['profile_logo_url'],
            'place_id' => $place_id
          );
        }

        // Add message to the grouped messages
        $grouped_messages[$other_id]['messages'][] = array(
            'id'=>$message->id,
            'sender_id' => $sender_id,
            'receiver_id' => $receiver_id,
            'sender_type' =>$message->sender_type,
            'content' => $message->content,
            'receiver_type'=> $message->receiver_type,
            'details' => !empty($message->details) ? process_message_details($message->details) : null,
            'created_at' => $message->created_at
        );
    }

   // Add grouped messages to the conversations array
    foreach ($grouped_messages as $conversation) {
        // Ensure place details are added to the top
       $conversation = array_merge($conversation['place'], $conversation);
       $conversations[] = $conversation;
    }
}

// Step 3: Fetch all unique users the given user has talked to, excluding places
$query = "
    SELECT DISTINCT
        GREATEST(sender_id, receiver_id) AS user1,
        LEAST(sender_id, receiver_id) AS user2,
        CASE
            WHEN sender_id = %d THEN receiver_type
            ELSE sender_type
        END AS other_type,
        CASE
            WHEN sender_id = %d THEN receiver_id
            ELSE sender_id
        END AS other_id
    FROM wp_voxel_messages
    WHERE (sender_id = %d OR receiver_id = %d)
      AND (
            (sender_type = 'user' AND receiver_type = 'user') OR
            (sender_type = 'post' AND receiver_type = 'user') OR
            (sender_type = 'user' AND receiver_type = 'post')
        )
";
$results = $wpdb->get_results($wpdb->prepare($query, $user_id, $user_id, $user_id, $user_id, $user_id));

// Group messages by user or post
foreach ($results as $result) {
    $other_user_id = intval($result->other_id);
    $other_type = $result->other_type;

    // Fetch profile based on the other type
    $profile = get_profile($other_user_id, $other_type);

    // Fetch all messages between the current user and the other user or post
    $messages_query = "
        SELECT *
        FROM wp_voxel_messages
        WHERE (sender_id = %d AND receiver_id = %d)
           OR (sender_id = %d AND receiver_id = %d)
        ORDER BY created_at DESC
    ";
    $messages = $wpdb->get_results($wpdb->prepare($messages_query, $user_id, $other_user_id, $other_user_id, $user_id), ARRAY_A);

    foreach ($messages as &$message) {
        if (!empty($message['details'])) {
            $details = json_decode($message['details'], true);
            if (isset($details['files'])) {
                // Assuming files are stored in the wp-content/uploads directory
                $message['details'] = wp_get_attachment_url($details['files']);
            } else {
                $message['details'] = null;
            }
        } else {
            $message['details'] = null;
        }
    }

    // Add to conversations array
    $conversations[] = array(
        'user_id' => $other_user_id,
        'type' => $other_type,
        'profile' => $profile,
        'messages' => $messages,
    );
     usort($conversations, function($a, $b) {
      $a_latest_time = strtotime($a['messages'][0]['created_at']);
      $b_latest_time = strtotime($b['messages'][0]['created_at']);
      return $b_latest_time - $a_latest_time;
  });
}

// Return the results
return rest_ensure_response($conversations);


  }

  function get_user_profile($user_id) {
    global $wpdb;

    // Fetch basic user info from wp_users
    $user_info = $wpdb->get_row($wpdb->prepare("
      SELECT ID, user_login, user_nicename, user_email, user_url, display_name
      FROM wp_users
      WHERE ID = %d
    ", $user_id), ARRAY_A);

    if (!$user_info) {
      return null;
    }

    // Fetch nickname from wp_usermeta
    $nickname = $wpdb->get_var($wpdb->prepare("
      SELECT meta_value
      FROM wp_usermeta
      WHERE user_id = %d AND meta_key = 'nickname'
    ", $user_id));

    $user_info['nickname'] = $nickname;
    $user_info['profile_pic'] = get_avatar_url($user_id);

    return $user_info;
  }
   function get_post_profile($post_id) {
    global $wpdb;

    // Fetch basic post info from wp_posts
    $post_info = $wpdb->get_row($wpdb->prepare("
      SELECT ID, post_title
      FROM wp_posts
      WHERE ID = %d AND post_type = 'places'
    ", $post_id), ARRAY_A);

    if (!$post_info) {
      return null;
    }
    $post_info['display_name'] = $post_info['post_title']; 
    // Fetch logo URL from post meta
    $post_info['profile_pic'] = $this->get_post_logo_url($post_id);

    return $post_info;
  }
   function get_post_logo_url($post_id) {
        // Fetch logo URL from post meta
        $logo_id = get_post_meta($post_id, 'logo', true);
        return wp_get_attachment_url($logo_id);
    }
  function is_user($id) {
    global $wpdb;

    $user = get_user_by('ID', $id);

    return $user !== false;
  }
  function is_post($id) {
    $post = get_post($id);

    return $post !== null && $post->post_type === 'places';
 }
}

$Voxel_Messages =new Voxel_Messages();
class GetNewsFeed
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes()
  {
    register_rest_route(
      'Voxel/v1',
      '/news-feed',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'get_news_feed'),
      )
    );
  }

  function get_news_feed($request)
  {
    global $wpdb;

   // Prepare SQL query to fetch all records from wp_voxel_timeline
   $query = "SELECT * FROM {$wpdb->prefix}voxel_timeline ORDER BY created_at DESC";
   $results = $wpdb->get_results($query, ARRAY_A);

   if ($results) {
    $formatted_feed = array();
    $feed_ids = array(); // To keep track of added feed items
     foreach ($results as $result) {
     // Check for duplicate entries
    if (in_array($result['id'], $feed_ids)) {
    continue;
    }
    // Decode JSON safely
    $details = !empty($result['details']) ? json_decode($result['details'], true) : array();

    if (isset($details['files'])) {
      $file_ids = explode(',', $details['files']);
      $files_with_urls = array();
      foreach ($file_ids as $file_id) {
        $file_url = wp_get_attachment_url($file_id);
        if ($file_url) {
          $files_with_urls[] = array(
            'id' => $file_id,
            'url' => $file_url,
          );
        }
      }
      $details['files'] = $files_with_urls;
    }

    // Fetch user information
    $user_info = get_userdata($result['user_id']);

     // Count likes for this timeline entry
    $timeline_likes_count = $wpdb->get_var($wpdb->prepare(
      "SELECT COUNT(*) FROM {$wpdb->prefix}voxel_timeline_likes WHERE status_id = %d",
      $result['id']
    ));

    // Prepare the main feed item
    $feed_item = array(
      'id' => $result['id'],
      'user_id' => $result['user_id'],
      'profile_pic_url' => get_avatar_url($result['user_id']),
      'user_name' => $user_info ? $user_info->display_name : 'Unknown',
      'post_id' => $result['post_id'],
      'content' => $result['content'],
      'details' => $details,
      'review_score' => $result['review_score'],
      'likes_count' => $timeline_likes_count,
      'created_at' => $result['created_at'],
      'edited_at' => $result['edited_at'],
      'replies' => array(), // Initialize replies array
       );

    // Fetch replies for this timeline entry
    $replies_query = $wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}voxel_timeline_replies WHERE status_id = %d ORDER BY created_at DESC",
      $result['id']
    );
    $replies_results = $wpdb->get_results($replies_query, ARRAY_A);

    foreach ($replies_results as $reply) {
      // Check for duplicate replies
      if (in_array($reply['id'], $feed_ids)) {
        continue;
      }

      $reply_details = !empty($reply['details']) ? json_decode($reply['details'], true) : array();

      if (isset($reply_details['files'])) {
        $reply_file_ids = explode(',', $reply_details['files']);
        $reply_files_with_urls = array();
        foreach ($reply_file_ids as $file_id) {
          $file_url = wp_get_attachment_url($file_id);
          if ($file_url) {
            $reply_files_with_urls[] = array(
              'id' => $file_id,
              'url' => $file_url,
            );
          }
        }
        $reply_details['files'] = $reply_files_with_urls;
      }

      $reply_user_info = get_userdata($reply['user_id']);

     // Count likes for this reply
      $reply_likes_count = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->prefix}voxel_timeline_reply_likes WHERE reply_id = %d",
        $reply['id']
      ));

      // Prepare reply item
      $reply_item = array(
        'id' => $reply['id'],
        'user_id' => $reply['user_id'],
        'profile_pic_url' => get_avatar_url($reply['user_id']),
        'user_name' => $reply_user_info ? $reply_user_info->display_name : 'Unknown',
        'content' => $reply['content'],
        'details' => $reply_details,
        'likes_count' => $reply_likes_count,
        'created_at' => $reply['created_at'],
        'edited_at' => $reply['edited_at'],
        'replies' => array(), // Initialize nested replies array
        );

      // Fetch nested replies for this reply
      $nested_replies_query = $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}voxel_timeline_replies WHERE parent_id = %d ORDER BY created_at DESC",
        $reply['id']
      );
      $nested_replies_results = $wpdb->get_results($nested_replies_query, ARRAY_A);

      foreach ($nested_replies_results as $nested_reply) {
        // Check for duplicate nested replies
        if (in_array($nested_reply['id'], $feed_ids)) {
          continue;
        }

        $nested_reply_details = !empty($nested_reply['details']) ? json_decode($nested_reply['details'], true) : array();

        if (isset($nested_reply_details['files'])) {
          $nested_reply_file_ids = explode(',', $nested_reply_details['files']);
          $nested_reply_files_with_urls = array();
          foreach ($nested_reply_file_ids as $file_id) {
            $file_url = wp_get_attachment_url($file_id);
            if ($file_url) {
              $nested_reply_files_with_urls[] = array(
                'id' => $file_id,
                'url' => $file_url,
              );
            }
          }
          $nested_reply_details['files'] = $nested_reply_files_with_urls;
        }

        $nested_reply_user_info = get_userdata($nested_reply['user_id']);

        // Count likes for this nested reply
        $nested_reply_likes_count = $wpdb->get_var($wpdb->prepare(
          "SELECT COUNT(*) FROM {$wpdb->prefix}voxel_timeline_reply_likes WHERE reply_id = %d",
          $nested_reply['id']
        ));

        $reply_item['replies'][] = array(
          'id' => $nested_reply['id'],
          'user_id' => $nested_reply['user_id'],
          'profile_pic_url' => get_avatar_url($nested_reply['user_id']),
          'user_name' => $nested_reply_user_info ? $nested_reply_user_info->display_name : 'Unknown',
          'content' => $nested_reply['content'],
          'details' => $nested_reply_details,
          'likes_count' => $nested_reply_likes_count,
          'created_at' => $nested_reply['created_at'],
          'edited_at' => $nested_reply['edited_at'],
        );

        // Add nested reply to the feed_ids array
        $feed_ids[] = $nested_reply['id'];
      }

      // Add the reply to the main feed item
      $feed_item['replies'][] = $reply_item;

      // Add reply to the feed_ids array
      $feed_ids[] = $reply['id'];
    }

    // Add the feed item to the formatted feed
    $formatted_feed[] = $feed_item;

    // Add feed item to the feed_ids array
    $feed_ids[] = $result['id'];
  }

  return rest_ensure_response(array(
    'news_feed' => $formatted_feed,
  ));
} else {
  return rest_ensure_response(array(
    'message' => 'No news feed found',
  ));
  }  
  }
}

$getNewsFeed = new GetNewsFeed();
class UserFollow {

  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/follow',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'handle_follow_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
    register_rest_route(
      'Voxel/v1',
      '/unfollow',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'handle_unfollow_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
    register_rest_route(
        'Voxel/v1',
        '/check-follow',
        array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_check_follow_request'),
        )
    );
  }

  function handle_follow_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $follower_id = isset($params['follower_id']) ? absint($params['follower_id']) : 0;
    $followed_id = isset($params['followed_id']) ? absint($params['followed_id']) : 0;

    if (empty($follower_id) || empty($followed_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // Check if the relationship already exists
    $existing_relationship = $wpdb->get_row($wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}voxel_followers
      WHERE follower_type = 'user' AND follower_id = %d AND object_type = 'user' AND object_id = %d",
      $follower_id, $followed_id
    ));

    if ($existing_relationship) {
      // Update existing relationship if needed
      if ($existing_relationship->status !== 1) {
          $wpdb->update(
              $wpdb->prefix . 'voxel_followers',
              array('status' => 1),
              array(
                  'follower_type' => 'user',
                  'follower_id' => $follower_id,
                  'object_type' => 'user',
                  'object_id' => $followed_id,
              )
          );
      }
  } else {
      // Create new relationship
      $wpdb->insert(
        $wpdb->prefix . 'voxel_followers',
        array(
          'follower_type' => 'user',
          'follower_id' => $follower_id,
          'object_type' => 'user',
          'object_id' => $followed_id,
          'status' => 1, // 1 indicates active status, adjust as needed
        )
      );
    }

    // Update follow stats for both users
    $this->update_follow_stats($follower_id);
    $this->update_follow_stats($followed_id);

    return new \WP_REST_Response(array('message' => 'Follower relationship updated'));
  }

  function handle_unfollow_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $follower_id = isset($params['follower_id']) ? absint($params['follower_id']) : 0;
    $followed_id = isset($params['followed_id']) ? absint($params['followed_id']) : 0;

    if (empty($follower_id) || empty($followed_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // Check if the relationship exists
    $existing_relationship = $wpdb->get_row($wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}voxel_followers
      WHERE follower_type = 'user' AND follower_id = %d AND object_type = 'user' AND object_id = %d",
      $follower_id, $followed_id
    ));

    if ($existing_relationship) {
      // Update relationship to indicate unfollow
      $wpdb->update(
        $wpdb->prefix . 'voxel_followers',
        array('status' => 0), // 0 indicates inactive status, adjust as needed
        array(
            'follower_type' => 'user',
            'follower_id' => $follower_id,
            'object_type' => 'user',
            'object_id' => $followed_id,
        )
      );

      // Update follow stats for both users
      $this->update_follow_stats($follower_id);
      $this->update_follow_stats($followed_id);

      return new \WP_REST_Response(array('message' => 'Follower relationship updated'));
    } else {
      return new \WP_REST_Response(array('message' => 'Relationship not found'));
    }
  }

  function update_follow_stats($user_id) {
    global $wpdb;

    // Fetch and update follow stats
    $stats = [
      'following' => [],
      'followed' => [],
    ];

    // Get following stats
    $following = $wpdb->get_results($wpdb->prepare(
      "SELECT status, COUNT(*) AS count
      FROM {$wpdb->prefix}voxel_followers
      WHERE follower_type = 'user' AND follower_id = %d
      GROUP BY status",
      $user_id
    ));

    foreach ($following as $status) {
      $stats['following'][(int)$status->status] = absint($status->count);
    }

    // Get followed by stats
    $followed = $wpdb->get_results($wpdb->prepare(
      "SELECT status, COUNT(*) AS count
      FROM {$wpdb->prefix}voxel_followers
      WHERE object_type = 'user' AND object_id = %d
      GROUP BY status",
      $user_id
    ));

    foreach ($followed as $status) {
      $stats['followed'][(int)$status->status] = absint($status->count);
    }

    // Update user meta with the stats
    update_user_meta($user_id, 'voxel:follow_stats', wp_slash(wp_json_encode($stats)));
  }
   function handle_check_follow_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $follower_id = isset($params['follower_id']) ? absint($params['follower_id']) : 0;
    $followed_id = isset($params['followed_id']) ? absint($params['followed_id']) : 0;

    if (empty($follower_id) || empty($followed_id)) {
        return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // Check follow status for both user and post types
    $statuses = [];
    $types = ['user', 'post'];
    $following = false;

    foreach ($types as $type) {
      $existing_relationship = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}voxel_followers
        WHERE follower_type = 'user' AND follower_id = %d AND object_type = %s AND object_id = %d AND status = 1",
        $follower_id, $type, $followed_id
      ));

      if ($existing_relationship) {
        $following = true;
            break; // No need to check further if already following
        }
    }

   if ($following) {
     return new \WP_REST_Response(array('status' => true));
    } else {
      return new \WP_REST_Response(array('status' => false));
    }
  }
}

$UserFollow = new UserFollow();
class PlaceFollow {

  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/follow_place',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'handle_follow_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
    register_rest_route(
      'Voxel/v1',
      '/unfollow_place',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'handle_unfollow_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
  }

  function handle_follow_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $follower_id = isset($params['follower_id']) ? absint($params['follower_id']) : 0;
    $followed_post_id = isset($params['followed_post_id']) ? absint($params['followed_post_id']) : 0;

    if (empty($follower_id) || empty($followed_post_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // Check if the relationship already exists
    $existing_relationship = $wpdb->get_row($wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}voxel_followers
      WHERE follower_type = 'user' AND follower_id = %d AND object_type = 'post' AND object_id = %d",
      $follower_id, $followed_post_id
    ));

    if ($existing_relationship) {
      // Update existing relationship if needed
      if ($existing_relationship->status !== 1) {
          $wpdb->update(
              $wpdb->prefix . 'voxel_followers',
              array('status' => 1),
              array(
                  'follower_type' => 'user',
                  'follower_id' => $follower_id,
                  'object_type' => 'post',
                  'object_id' => $followed_post_id,
              )
          );
      }
    } else {
      // Create new relationship
      $wpdb->insert(
        $wpdb->prefix . 'voxel_followers',
        array(
          'follower_type' => 'user',
          'follower_id' => $follower_id,
          'object_type' => 'post',
          'object_id' => $followed_post_id,
          'status' => 1, // 1 indicates active status, adjust as needed
        )
      );
    }

    // Update follow stats for the post
    $this->update_follow_stats($followed_post_id);

    return new \WP_REST_Response(array('message' => 'Follow relationship updated'));
  }

  function handle_unfollow_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $follower_id = isset($params['follower_id']) ? absint($params['follower_id']) : 0;
    $followed_post_id = isset($params['followed_post_id']) ? absint($params['followed_post_id']) : 0;

    if (empty($follower_id) || empty($followed_post_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // Check if the relationship exists
    $existing_relationship = $wpdb->get_row($wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}voxel_followers
      WHERE follower_type = 'user' AND follower_id = %d AND object_type = 'post' AND object_id = %d",
      $follower_id, $followed_post_id
    ));

    if ($existing_relationship) {
      // Update relationship to indicate unfollow
      $wpdb->update(
        $wpdb->prefix . 'voxel_followers',
        array('status' => 0), // 0 indicates inactive status, adjust as needed
        array(
            'follower_type' => 'user',
            'follower_id' => $follower_id,
            'object_type' => 'post',
            'object_id' => $followed_post_id,
        )
      );

      // Update follow stats for the post
      $this->update_follow_stats($followed_post_id);

      return new \WP_REST_Response(array('message' => 'Follow relationship updated'));
    } else {
      return new \WP_REST_Response(array('message' => 'Relationship not found'));
    }
  }

  function update_follow_stats($post_id) {
    global $wpdb;

    $stats = [
        'followed' => [],
    ];

    // Followed stats
    $followed = $wpdb->get_results($wpdb->prepare(
        "SELECT `status`, COUNT(*) AS `count`
        FROM {$wpdb->prefix}voxel_followers
        WHERE `object_type` = 'post' AND `object_id` = %d
        GROUP BY `status`",
        $post_id
    ));

    foreach ($followed as $status) {
        $stats['followed'][(int) $status->status] = absint($status->count);
    }

    update_post_meta($post_id, 'voxel:follow_stats', wp_slash(wp_json_encode($stats)));
    return $stats;
  }
}

// Initialize the class
$PlaceFollow =new PlaceFollow();

// Like or unlike for timeline and reply
class LikeTimeline {
  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/like-timeline',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'like_timeline'),
      )
    );
    register_rest_route(
      'Voxel/v1', 
      '/reply-like', 
      array(
        'methods' => 'POST',
        'callback' => array($this, 'like_timeline_reply'),
    ));
  }

  function like_timeline($request) {
    global $wpdb;
    $user_id = $request->get_param('id');
    $status_id = $request->get_param('status_id');
    $action = $request->get_param('action'); // 'like' or 'unlike'

    if ($action === 'like') {
      // Check if the user has already liked this status
      $already_liked = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->prefix}voxel_timeline_likes WHERE user_id = %d AND status_id = %d",
        $user_id,
        $status_id
      ));

      if ($already_liked) {
        return rest_ensure_response(array(
          'message' => 'You have already liked this status.',
        ));
      }

      // Insert the like
      $insert = $wpdb->insert(
        "{$wpdb->prefix}voxel_timeline_likes",
        array(
          'user_id' => $user_id,
          'status_id' => $status_id
        ),
        array(
          '%d',
          '%d'
        )
      );

      if ($insert) {
        return rest_ensure_response(array(
          'message' => 'Liked successfully.'
        ));
      } else {
        return rest_ensure_response(array(
          'message' => 'Error liking the status.'
        ));
      }
    } elseif ($action === 'unlike') {
      // Delete the like
      $delete = $wpdb->delete(
        "{$wpdb->prefix}voxel_timeline_likes",
        array(
          'user_id' => $user_id,
          'status_id' => $status_id
        ),
        array(
          '%d',
          '%d'
        )
      );

      if ($delete) {
        return rest_ensure_response(array(
          'message' => 'Unliked successfully.'
        ));
      } else {
        return rest_ensure_response(array(
          'message' => 'Error unliking the status.'
        ));
      }
    } else {
      return rest_ensure_response(array(
        'message' => 'Invalid action.'
      ));
    }
  }
  function like_timeline_reply($request) {
    global $wpdb;
    
    $user_id = $request->get_param('id');
    $reply_id = $request->get_param('reply_id');
    $action = $request->get_param('action'); // 'like' or 'unlike'

    if ($action === 'like') {
        // Check if the user has already liked this reply
        $already_liked = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}voxel_timeline_reply_likes WHERE user_id = %d AND reply_id = %d",
            $user_id,
            $reply_id
        ));

        if ($already_liked) {
            return rest_ensure_response(array(
                'message' => 'You have already liked this reply.'
            ));
        }

        // Insert the like
        $insert = $wpdb->insert(
            "{$wpdb->prefix}voxel_timeline_reply_likes",
            array(
                'user_id' => $user_id,
                'reply_id' => $reply_id
            ),
            array(
                '%d',
                '%d'
            )
        );

        if ($insert) {
            return rest_ensure_response(array(
                'message' => 'Liked reply successfully.'
            ));
        } else {
            return rest_ensure_response(array(
                'message' => 'Error liking the reply.'
            ));
        }
    } elseif ($action === 'unlike') {
        // Delete the like
        $delete = $wpdb->delete(
            "{$wpdb->prefix}voxel_timeline_reply_likes",
            array(
                'user_id' => $user_id,
                'reply_id' => $reply_id
            ),
            array(
                '%d',
                '%d'
            )
        );

        if ($delete) {
            return rest_ensure_response(array(
                'message' => 'Unliked reply successfully.'
            ));
        } else {
            return rest_ensure_response(array(
                'message' => 'Error unliking the reply.'
            ));
        }
    } else {
        return rest_ensure_response(array(
            'message' => 'Invalid action.'
        ));
    }
  }
}
$LikeTimeline =new LikeTimeline();

class Replytimeline{
 function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/reply-timeline',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'insert_timeline_reply'),
      )
    );
  }
  function insert_timeline_reply($request) {
    global $wpdb;

    $user_id = $request->get_param('user_id');
    $status_id = $request->get_param('status_id');
    $parent_id = isset($request['parent_id']) ? $request->get_param('parent_id') : null;
    $content = $request->get_param('content');
    $details = isset($request['details']) ? $request->get_param('details') : null;


    $table_name = $wpdb->prefix . 'voxel_timeline_replies';

    $result = $wpdb->insert(
        $table_name,
        array(
            'user_id' => $user_id,
            'status_id' => $status_id,
            'parent_id' => $parent_id,
            'content' => $content,
            'details' => $details,
            'created_at' => current_time('mysql')
        ),
        array(
            '%d', // user_id
            '%d', // status_id
            '%d', // parent_id
            '%s', // content
            '%s', // details
            '%s'  // created_at
        )
    );

    if ($result !== false) {
        return new \WP_REST_Response(array('message' => 'Reply inserted successfully.'));
    } else {
        return new \WP_REST_Response(array('message' => 'Error inserting reply.'));
    }
  }
}
$Replytimeline = new Replytimeline();

class Deletetimeline{
function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/delete-timeline-reply',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'delete_timeline_reply'),
      )
    );
  }
  function delete_timeline_reply($request) {
    global $wpdb;

    $reply_id = $request->get_param('reply_id');

    $table_name = $wpdb->prefix . 'voxel_timeline_replies';

    $result = $wpdb->delete(
        $table_name,
        array('id' => $reply_id),
        array('%d')
    );

    if ($result !== false) {
        return new \WP_REST_Response(array('message' => 'Reply deleted successfully.'));
    } else {
        return new \WP_REST_Response(array('message' => 'Error deleting reply.'));
    }
  }
}

$Deletetimeline =new Deletetimeline ();
// Collection apis
class CollectionAPI {

  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/add_collection',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'handle_add_collection_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );

    register_rest_route(
      'Voxel/v1',
      '/remove_collection',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'handle_remove_collection_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
    register_rest_route(
      'Voxel/v1',
      '/get_collections_by_author/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'handle_get_collections_by_author_request'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
  }

  function handle_add_collection_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $post_author = isset($params['id']) ? absint($params['id']) : 0;
    $post_title = isset($params['post_title']) ? sanitize_text_field($params['post_title']) : '';
    $collection_id = isset($params['collection_id']) ? absint($params['collection_id']) : 0;
    $place_id = isset($params['place_id']) ? absint($params['place_id']) : 0;

    if (empty($post_author)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // If collection_id is provided, update the existing collection
    if ($collection_id) {
      $existing_collection = get_post($collection_id);

      if ($existing_collection && $existing_collection->post_type === 'collection' && $existing_collection->post_author == $post_author) {
        // Update collection details if post_title is provided
        if (!empty($post_title)) {
          wp_update_post(array(
            'ID' => $collection_id,
            'post_title' => $post_title,
                'post_name' => sanitize_title($post_title), // Ensure post_name is sanitized
              ));
        }

        // Handle place association if place_id is provided
        if ($place_id) {
          $wpdb->insert(
            $wpdb->prefix . 'voxel_relations',
            array(
              'parent_id' => $collection_id,
              'child_id' => $place_id,
              'relation_key' => 'items',
              'order' => 0
            ),
            array('%d', '%d', '%s', '%d')
          );
        }

        return new \WP_REST_Response(array('message' => 'Collection updated successfully', 'collection_id' => $collection_id));
      } else {
        return new \WP_REST_Response(array('message' => 'Collection not found or access denied'));
      }
    }

    // If no collection_id is provided, check for an existing collection by author and title
    $existing_collection = $wpdb->get_row($wpdb->prepare(
      "SELECT ID FROM {$wpdb->posts} 
      WHERE post_author = %d AND post_title = %s AND post_type = 'collection' AND post_status = 'publish'",
      $post_author, $post_title
    ));

    if ($existing_collection) {
      $post_id = $existing_collection->ID;
    } else {
    // Insert new post into wp_posts
      $new_post = array(
        'post_author' => $post_author,
        'post_title' => $post_title,
        'post_name' => sanitize_title($post_title), // Ensure post_name is sanitized
        'post_status' => 'publish',
        'post_type' => 'collection'
      );

      $post_id = wp_insert_post($new_post);

      if (is_wp_error($post_id)) {
        return new \WP_REST_Response(array('message' => 'Failed to create collection'));
      }

    // Insert into wp_voxel_index_collection table
      $wpdb->insert(
        $wpdb->prefix . 'voxel_index_collection',
        array(
          'post_id' => $post_id,
          'post_status' => 'publish',
          '_keywords' => $post_title
        ),
        array('%d', '%s', '%s')
      );

      if (!$wpdb->insert_id) {
        // Rollback the post creation if collection insert fails
        wp_delete_post($post_id, true);
        return new \WP_REST_Response(array('message' => 'Failed to add collection to index'));
      }
    }

    // If place_id is provided, add place to collection
    if ($place_id) {
      $wpdb->insert(
        $wpdb->prefix . 'voxel_relations',
        array(
          'parent_id' => $post_id,
          'child_id' => $place_id,
          'relation_key' => 'items',
          'order' => 0
        ),
        array('%d', '%d', '%s', '%d')
      );
    }

    return new \WP_REST_Response(array('message' => 'Collection added successfully', 'collection_id' => $post_id));

  }
  

  function handle_remove_collection_request($request) {
    global $wpdb;
    $params = $request->get_params();
    $collection_id = isset($params['collection_id']) ? absint($params['collection_id']) : 0;

    if (empty($collection_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }

    // Delete from wp_posts table
    $deleted_post = wp_delete_post($collection_id, true);

    if (!$deleted_post) {
      return new \WP_REST_Response(array('message' => 'Failed to delete collection'));
    }

    // Delete from wp_voxel_index_collection table
    $deleted_index = $wpdb->delete(
      $wpdb->prefix . 'voxel_index_collection',
      array('post_id' => $collection_id),
      array('%d')
    );

    // Delete related entries from wp_voxel_relations table
    $wpdb->delete(
      $wpdb->prefix . 'voxel_relations',
      array('parent_id' => $collection_id),
      array('%d')
    );

    if ($deleted_index !== false) {
      return new \WP_REST_Response(array('message' => 'Collection removed successfully'));
    } else {
      return new \WP_REST_Response(array('message' => 'Failed to delete collection from index'));
    }
  }
  function handle_get_collections_by_author_request($request) {
    global $wpdb;
    $params = $request->get_params('id');
    $author_id = isset($params['id']) ? absint($params['id']) : 0;

    if (empty($author_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'), 400);
    }

    $collections = $wpdb->get_results($wpdb->prepare(
      "SELECT ID, post_title FROM {$wpdb->posts}
      WHERE post_author = %d AND post_type = 'collection' AND post_status = 'publish'",
      $author_id
    ));

    if ($collections) {
      $collections_data = array();
      foreach ($collections as $collection) {
        $collections_data[] = array(
          'ID' => $collection->ID,
          'post_title' => $collection->post_title
        );
      }
      return new \WP_REST_Response(array('collections' => $collections_data));
    } else {
      return new \WP_REST_Response(array('message' => 'No collections found for the author'));
    }
  }
}

$CollectionAPI =new CollectionAPI();

class checkcollection{
  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }
  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/collection-check',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'collctioncheck'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
  }

  function collctioncheck($request){
    global $wpdb;
    $params = $request->get_params();
    $user_id = isset($params['user_id']) ? absint($params['user_id']) : 0;
    $place_id = isset($params['place_id']) ? absint($params['place_id']) : 0;
    
    if (empty($user_id) || empty($place_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }
    
    // Query to check if user_id and place_id exist in the collection
    $query = $wpdb->prepare(
      "SELECT COUNT(*) FROM {$wpdb->prefix}voxel_relations 
      WHERE parent_id IN (
        SELECT ID FROM {$wpdb->posts} 
        WHERE post_author = %d AND post_type = 'collection' AND post_status = 'publish'
      ) AND child_id = %d AND relation_key = 'items'",
      $user_id, $place_id
    );
    
    $exists_in_collection = $wpdb->get_var($query);
    
    if ($exists_in_collection) {
      return new \WP_REST_Response(array('in_collection' => true));
    } else {
      return new \WP_REST_Response(array('in_collection' => false));
    }
  }
}

$checkcollection = new checkcollection();
class reviewreply
{
  function __construct() {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  function register_routes() {
    register_rest_route(
      'Voxel/v1',
      '/review_post',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'review_reply'),
        // 'permission_callback' => '__return_true', // Adjust permissions as needed
      )
    );
  }

  function review_reply(\WP_REST_Request $request) {
    global $wpdb;

    // Extract parameters from the request
    $post_id = $request->get_param('post_id');
    $user_id = $request->get_param('user_id');
    $message = $request->get_param('content') !== null ? $request->get_param('content') : '';
    $overall = $request->get_param('overall') !== null ? $request->get_param('overall') : '';
    $service = $request->get_param('service') !== null ? $request->get_param('service') : '';
    $hospitality = $request->get_param('hospitality') !== null ? $request->get_param('hospitality') : '';
    $pricing = $request->get_param('pricing') !== null ? $request->get_param('pricing') : '';
    $files = isset($_FILES['gallery']) ? $_FILES['gallery'] : array();
    
    if (empty($user_id) || empty($post_id)) {
      return new \WP_REST_Response(array('message' => 'Missing parameters'));
    }
    // Combine individual ratings into the rating array
    $rating_data = array(
        'overall' => $overall,
        'service' => $service,
        'hospitality' => $hospitality,
        'pricing' => $pricing,
    );
    
    // Check if the timeline entry exists for the given post_id and user_id
    $entry = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}voxel_timeline WHERE post_id = %d AND user_id = %d",
        $post_id, $user_id
    ), ARRAY_A);
    
    if ($entry) {
        // If entry is found, proceed with the update
        $timeline_id = $entry['id'];
    } else {
        // No entry found, set flag to insert a new one
        $timeline_id = null;
    }
    
    // Process and adjust the rating scores
    if (!empty($rating_data)) {
        // Adjust the individual rating scores
        $review_score_adjusted = array(
            'score' => isset($rating_data['overall']) ? intval($rating_data['overall']) - 3 : null,
            'custom-660' => isset($rating_data['service']) ? intval($rating_data['service']) - 3 : null,
            'custom-978' => isset($rating_data['hospitality']) ? intval( $rating_data['hospitality']) - 3 : null,
            'custom-271' => isset($rating_data['pricing']) ? intval($rating_data['pricing']) - 3 : null
        );
    
        // Combine the adjusted scores
        $combined_score = 0;
        $score_count = 0;
        foreach ($review_score_adjusted as $score) {
            if ($score !== null) {
                $combined_score += $score;
                $score_count++;
            }
        }
    
        // Calculate the average score
        $final_review_score = $score_count > 0 ? ($combined_score / $score_count)  : null;
    
        // Update the details with the adjusted scores
        $details = $timeline_id ? json_decode($entry['details'], true) : array();
        $details['rating'] = $review_score_adjusted;
        $updated_details = json_encode($details);
    
        $updated_data = array(
            'details' => $updated_details,
            'review_score' => $final_review_score
        );
    } else {
        $updated_data = array();
    }
    
   // Handle file uploads
    if (!empty($files)) {
      $uploaded_file_ids = array();
      $file_count = count($files['name']);
      for ($i = 0; $i < $file_count; $i++) {
        $file = array(
          'name' => $files['name'][$i],
          'type' => $files['type'][$i],
          'tmp_name' => $files['tmp_name'][$i],
          'error' => $files['error'][$i],
          'size' => $files['size'][$i],
        );

        $uploaded_file = wp_handle_upload($file, array('test_form' => false));
        if (isset($uploaded_file['file'])) {
          $file_name = uniqid() . '-' . basename($uploaded_file['file']);
          $attachment = array(
            'guid' => $uploaded_file['url'],
            'post_mime_type' => $uploaded_file['type'],
            'post_title' => preg_replace('/\.[^.]+$/', '', $file_name),
            'post_content' => '',
            'post_status' => 'inherit'
          );
          $attachment_id = wp_insert_attachment($attachment, $uploaded_file['file']);
          if (!is_wp_error($attachment_id)) {
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            $attachment_data = wp_generate_attachment_metadata($attachment_id, $uploaded_file['file']);
            wp_update_attachment_metadata($attachment_id, $attachment_data);
            $uploaded_file_ids[] = $attachment_id;
          }
        }
      }

      if (!empty($uploaded_file_ids)) {
        $uploaded_files_str = implode(',', $uploaded_file_ids);
        $details['files'] = $uploaded_files_str;
        $updated_details = json_encode($details);
        $updated_data['details'] = $updated_details;
      }
    } else {
    // Perform any specific actions when no files are uploaded
    $details['files'] = ''; // Ensure 'files' key is set to an empty string
    $updated_details = json_encode($details);
    $updated_data['details'] = $updated_details;
    }

    // Insert or Update the database
    if ($timeline_id) {
        // Update existing entry
        $updated_data = array(
            'details' => $updated_details,
            'review_score' => $final_review_score
        );
        if (!empty($message)) {
            $updated_data['content'] = $message;
        }
    
        $wpdb->update(
            "{$wpdb->prefix}voxel_timeline",
            $updated_data,
            array('id' => $timeline_id),
            array('%s', '%f', '%s'),
            array('%d')
        );
        $message = 'Review updated successfully';
    } else {
        // Insert new entry
        $updated_data = array(
            'post_id' => $post_id,
            'user_id' => $user_id,
            'details' => $updated_details,
            'review_score' => $final_review_score,
            'content' => $message
        );
    
        $wpdb->insert(
            "{$wpdb->prefix}voxel_timeline",
            $updated_data,
            array('%d', '%d', '%s', '%f', '%s')
        );
        $timeline_id = $wpdb->insert_id; // Get the ID of the newly inserted row
        $message = 'Timeline inserted successfully';
     }
    
    // Update post meta with new review statistics
    $post = \Voxel\Post::get($post_id);
    
    $stats = [
        'total' => 0,
        'average' => null,
        'by_score' => [],
        'by_category' => [],
        'latest' => null,
    ];
    
    $results = $wpdb->get_row($wpdb->prepare(<<<SQL
        SELECT AVG(review_score) AS average, COUNT(review_score) AS total
        FROM {$wpdb->prefix}voxel_timeline
        WHERE post_id = %d AND review_score IS NOT NULL
    SQL, $post_id));
    
    if (is_numeric($results->average) && is_numeric($results->total) && $results->total > 0) {
        $stats['total'] = absint($results->total);
        $stats['average'] = \Voxel\clamp($results->average, -2, 2);
    
        $by_score = $wpdb->get_results($wpdb->prepare(<<<SQL
            SELECT ROUND(review_score) AS score, COUNT(review_score) AS total
            FROM {$wpdb->prefix}voxel_timeline
            WHERE post_id = %d AND review_score BETWEEN -2 AND 2
            GROUP BY ROUND(review_score)
        SQL, $post_id));
    
        foreach ($by_score as $score) {
            if (is_numeric($score->score) && is_numeric($score->total) && $score->total > 0) {
                $stats['by_score'][(int)$score->score] = absint($score->total);
            }
        }
    
        // Get the latest item
        $latest = $wpdb->get_row($wpdb->prepare(<<<SQL
            SELECT id, created_at, user_id, published_as
            FROM {$wpdb->prefix}voxel_timeline
            WHERE post_id = %d AND review_score IS NOT NULL
            ORDER BY created_at DESC LIMIT 1
        SQL, $post_id));
    
        if (is_numeric($latest->id ?? null) && strtotime($latest->created_at)) {
            $stats['latest'] = [
                'id' => absint($latest->id),
                'user_id' => is_numeric($latest->user_id) ? absint($latest->user_id) : null,
                'published_as' => is_numeric($latest->published_as) ? absint($latest->published_as) : null,
                'created_at' => date('Y-m-d H:i:s', strtotime($latest->created_at)),
            ];
        }
    }
    
    if ($post && $post->post_type) {
        $averages_sql = [];
        foreach ($post->post_type->reviews->get_categories() as $category) {
            $averages_sql[] = sprintf(
                "AVG(JSON_EXTRACT(details, '$.rating.\"%s\"')) AS `%s`",
                esc_sql($category['key']),
                esc_sql($category['key'])
            );
        }
    
        if (!empty($averages_sql)) {
            $select = join(', ', $averages_sql);
            $sql = $wpdb->prepare(<<<SQL
                SELECT {$select} FROM {$wpdb->prefix}voxel_timeline
                WHERE `post_id` = %d AND review_score IS NOT NULL
            SQL, $post->get_id());
            $results = $wpdb->get_row($sql, ARRAY_A);
            foreach ($results as $category_key => $category_average) {
                if (is_numeric($category_average)) {
                    $stats['by_category'][$category_key] = round($category_average, 3);
                }
            }
        }
    }
    
    update_post_meta($post_id, 'voxel:review_stats', wp_slash(wp_json_encode($stats)));
    
    // Return response
    return new \WP_REST_Response(array(
        'status' => true,
        'timeline_id' => $timeline_id,
        'message' => $message
    ));
  }
}

$reviewreply = new reviewreply();

//get user address by lat and long
class addressmap
{
  function __construct()
  {
    add_action('rest_api_init', array($this, 'addressmap'));
  }
  function addressmap()
  {
    register_rest_route(
      'Voxel/v1',
      '/address-user',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'address'),
      )
    );
  }
  function address($request) {
    $latitude = sanitize_text_field($request->get_param('latitude'));
    $longitude = sanitize_text_field($request->get_param('longitude'));

    if (empty($latitude) || empty($longitude)) {
        return new \WP_Error('no_coordinates', 'Latitude and longitude parameters are required', array('status' => 400));
    }

    $api_key = 'AIzaSyBLKiI-vWGHMb4NY6-dkpD20KHPGOnPDCg';
    $url = 'https://maps.googleapis.com/maps/api/geocode/json?latlng=' . urlencode($latitude) . ',' . urlencode($longitude) . '&key=' . $api_key;

    $response = wp_remote_get($url);

    if (is_wp_error($response)) {
        return new \WP_Error('api_request_failed', 'Failed to retrieve data from Google Maps API', array('status' => 500));
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if ($data['status'] !== 'OK') {
        return new \WP_Error('geolocation_failed', 'Failed to reverse geocode coordinates', array('status' => 400));
    }

    $address = $data['results'][0]['formatted_address'];
    $city = '';

    foreach ($data['results'][0]['address_components'] as $component) {
        if (in_array('locality', $component['types'])) {
            $city = $component['long_name'];
            break;
        }
    }

    if (empty($city)) {
        return new \WP_Error('city_not_found', 'City not found in the location data', array('status' => 400));
    }

    return rest_ensure_response(array(
        'city' => $city,
        'address' => $address,
    ));
    
  }
}
$addressmap = new addressmap();