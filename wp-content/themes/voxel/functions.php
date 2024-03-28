<?php

namespace Voxel;

if ( ! defined('ABSPATH') ) {
	exit;
}

function is_debug_mode() {
	return defined('WP_DEBUG') && WP_DEBUG;
}

function is_dev_mode() {
	return defined('VOXEL_DEV_MODE') && VOXEL_DEV_MODE;
}

function is_running_tests() {
	return defined('VOXEL_RUNNING_TESTS') && VOXEL_RUNNING_TESTS;
}

require_once locate_template('app/utils/utils.php');

require_once(ABSPATH.'wp-admin/includes/user.php');

include(ABSPATH . "wp-includes/pluggable.php"); 

foreach ( \Voxel\config('controllers') as $controller ) {
	new $controller;
}



 
class myapiendpoints {

  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'uheme_routes') );
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


class userpost{
  
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'user_post') );
  }
  function user_post()
  {
    register_rest_route(
      'Voxel/v1',
      '/user',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'userreg'),
        
      )
    );
  }
  
function userreg(\WP_REST_Request $request ) {
  $user_data = $request->get_params();
  
  // wpmu_validate_user_signup( $user_data['user_login'], $user_data['user_email'] );
  
  if (empty($user_data['user_login']) || empty($user_data['user_email']) || empty($user_data['user_pass']) ||empty($user_data['first_name']) || empty($user_data['last_name'])) {
       
    return new \WP_Error('inalid_credentials', 'some emapty credentials ', array('status' => 400));
  }

  if ( email_exists( $user_data['user_email'] ) ) {
    return new \WP_Error( 'user_creation_failed', __( 'Email and user is already in use', 'text-domain' ), array( 'status' => 400 ) );
  }
  if (!is_email($user_data['user_email'])) {
    return new \WP_Error('invalid_email', 'Invalid email format.', array('status' => 400));
  }
  
  if (strlen($user_data['user_pass']) < 4) {
    return new \WP_Error('weak_password', 'Password is too weak. Please use a stronger password.', array('status' => 400));
  }
  
  $user = wp_insert_user(array(
    'user_login' => $user_data['user_login'],
    'user_email' => $user_data['user_email'],
    'user_pass' => $user_data['user_pass'],
    'display_name'=> $user_data['first_name'].''.$user_data['last_name'],
    'roles' => 'Subscriber',
  ));

  if (is_wp_error($user)) {
    $error_code = $user->get_error_code();
    $error_message = Strip_tags($user->get_error_message());
    return new \WP_Error('user_creation_failed',__($error_message, 'text-domain'), array('status' => $error_code));
  }

  return array('message' => 'User created successfully', $user_data);
}
}
$user = new userpost();

class gologin{
function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'gologin') );
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
  function verify_google_token($token) {
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
   function userreg(){
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
              $error_message = Strip_tags( $user_id->get_error_message());
              return array('message' => 'User created successfully', $userdata);
            } else {
              $error_code = $user->get_error_code();
              $error_message = Strip_tags($user->get_error_message());
              return new \WP_Error('user_creation_failed',__($error_message, 'text-domain'), array('status' => $error_code));
            }
        } else {
          return new \WP_Error( 'user_creation_failed', __( 'Email and user is already in use', 'text-domain' ), array( 'status' => 400 ) );
        }
    } else {
      return new \WP_Error( 'user_creation_failed', __( 'Token verification failed,', 'text-domain' ), array( 'status' => 400 ) );
    }
   }
   
}



class updateuser{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'updateuser') );
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
  function update($request){
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



function generate_random_token() {
  return wp_generate_password(24, false);
}
class login{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'login') );
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
  function loginuser($request) {
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
      return new \WP_Error('invalid_credentials', $error_message , array('status' => $error_code ));
  }
  
  $token = generate_random_token();
  wp_set_current_user( $user->ID, $user->user_login );
  do_action( 'wp_login', $user->user_login, $user ); 
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

class getallu{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'getallu') );
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
  function getall($request){
    $users = get_users();
    $user_data = array();
    foreach ($users as $user) {
        $user_id = $user->ID;
        $user_name = $user->display_name;
        $profile_pic_url = get_avatar_url($user_id);

        $user_data[] = array(
            'id' => $user_id,
            'name' => $user_name,
            'profile_pic_url' => $profile_pic_url,
        );
    }

    return rest_ensure_response($user_data);
  }
}
$getallu =new getallu();


class deleteu{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'deleteu') );
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
  
  function deleteuser($request){
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

class passup{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'passres') );
  }
  function passres(){
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

  function pass($request){
  $user_data= $request->get_params();
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
$passup= new passup();


class forgotpass{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'forgotpass') );
  }
  function forgotpass(){
    register_rest_route(
      'Voxel/v1',
      '/forgotpass',
      array(
        'methods' => 'POST',
        'callback' => array($this, 'forgot'),
      )
    );
  }
  function forgot($request){
    $user_data = $request->get_params();
    
    if (empty($user_data['user_email'])) {
      return new \WP_Error('missing_data', 'Email is required.', array('status' => 400));
    }
    $email = sanitize_email($user_data['user_email']);
    $user = get_user_by('email', $email);
    
    if (!$user) {
      return new \WP_Error('user_not_found', 'User not found.', array('status' => 404));
    }
    $key = get_password_reset_key($user);

    if (is_wp_error($key)) {
        return new \WP_Error('key_generation_error', 'Error generating reset key.', array('status' => 500));
    }
    $reset_link = '<a href="' . site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user->user_login), 'login') . '">Reset Password</a>';
    $email_subject = 'Password Reset';
    $email_body = 'Please click the following link to reset your password: ' . $reset_link;
    // var_dump($reset_link);
    // die;
    $email_sent = wp_mail($email, $email_subject, $email_body);

    if (!$email_sent) {
        return new \WP_Error('email_send_error', 'Error sending email.', array('status' => 500));
    }

    return array(
        'message' => 'Password reset email sent.',
    );
  }
}
$forgotpass =new forgotpass();

class allpost{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'allpost') );
  }
  function allpost(){
    register_rest_route(
      'Voxel/v1',
      '/allpost',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request) {
    $posts = get_posts(array(
      'post_type' => 'places',
      'post_status' => 'publish',
      'posts_per_page' => -1, // Get all posts//-1(for all)
    ));

    if (empty($posts)) {
        return new \WP_Error('no_posts_found', 'No posts found.', array('status' => 404));
    }

    $formatted_posts = array();

    foreach ($posts  as $posts ) {
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
        $average_rating =isset($review_stats['average'])  ? round($review_stats['average'] +3,2) : ''; // Defaulting to '0' if not set
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
            $hours = $hours_data['hours'] ?? array();
    
            foreach ($days as $day) {
                if (!isset($formatted_opening_hours[$day])) {
                    $formatted_opening_hours[$day] = array();
                }
                if (!empty($hours)) {
                   foreach ($hours as $hour) {
                    $formatted_opening_hours[$day][] = $hour['from'] . '-' . $hour['to'];
                }
                }
                else {
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
            'Total Reviews'=>$total_reviews,
            'Average Rating' =>  $average_rating ,
            'opening_hours' => $formatted_opening_hours,
          
        );
    }
     return $formatted_posts;
}
}
$allpost =new allpost();

class postget{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'postget') );
  }
  function postget(){
    register_rest_route(
      'Voxel/v1',
      '/postget/(?P<id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request){
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
    foreach ($meta_data as $key => $value) {
      $meta_data[$key] = maybe_unserialize($value[0]);
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
      $timeline_entries[$entry->id] = array(
          'id' => $entry->id,
          'user_id' => $entry->user_id,
          'published_as' => $entry->published_as,
          'post_id' => $entry->post_id,
          'content' => $entry->content,
          'details' => $entry->details,
          'review_score' => $entry->review_score,
          'created_at' => $entry->created_at,
          'edited_at' => $entry->edited_at,
          'replies' => array(),
          'likes' => array(),
          'reply_likes' => array()// Initialize the likes array
      );
  }

  // If there is a like for this timeline entry, add it to the likes array
  if($entry->like_user_id && !$this->hasLike($timeline_entries[$entry->id]['likes'], $entry->like_user_id)) {
    $timeline_entries[$entry->id]['likes'][] = array(
        'like_user_id' => $entry->like_user_id,
        'like_status_id' => $entry->like_status_id
    );
}

  // If there is a reply for this timeline entry, add it to the replies array
  if ($entry->reply_id) {
      $timeline_entries[$entry->id]['replies'][] = array(
          'reply_id' => $entry->reply_id,
          'reply_user_id' => $entry->reply_user_id,
          'reply_content' => $entry->reply_content,
          'reply_details' => $entry->reply_details,
          'reply_created_at' => $entry->reply_created_at,
          'reply_edited_at' => $entry->reply_edited_at
      );
  }
  if ($entry->reply_like_user_id && !$this->hasLikea($timeline_entries[$entry->id]['reply_likes'], $entry->reply_like_user_id)) {
    $timeline_entries[$entry->id]['reply_likes'][] = array(
        'reply_like_user_id' => $entry->reply_like_user_id,
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
    ",$post_id);
    
    $related_parent_ids = $wpdb->get_results($query, ARRAY_A);

    $related_posts = array();
    foreach ($related_parent_ids as $related_parent_id) {
      $parent_post = get_post($related_parent_id['parent_id']);

      if ($parent_post && $parent_post->post_status === 'publish') {
          $profile_image_url = '';
          $profile_image_id = get_post_meta($parent_post->ID, 'logo', true);
          if ($profile_image_id) {
              $profile_image_url = wp_get_attachment_url($profile_image_id);
          }

          $related_posts[] = array(
              'id' => $parent_post->ID,
              'title' => $parent_post->post_title,
              //'content' => $parent_post->post_content,
              'profile_image_url' => $profile_image_url,
              'realtion_key' =>$related_parent_id['relation_key'],
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
        'timeline_entries' => $timeline_entries,
        'taxonomy_data'=>$taxonomy_data,
        'Posted by'=>$related_posts,
    );

    return rest_ensure_response($data);

  }
  function hasLike($likes, $user_id) {
    foreach ($likes as $like) {
        if ($like['like_user_id'] == $user_id) {
            return true;
        }
    }
    return false;
}
function hasLikea($likes, $user_id){
  foreach ($likes as $like) {
    if ($like['reply_like_user_id'] == $user_id) {
        return true;
    }
}
return false;
}
}
$postget = new postget();

class allevent{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'allevent') );
  }
  function allevent(){
    register_rest_route(
      'Voxel/v1',
      '/allevent',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request) {
    $events = get_posts(array(
      'post_type' => 'events',
      'post_status' => 'publish',
      'posts_per_page' => -1, // Get all posts//-1(for all)
    ));
    if (empty($events)) {
      return new \WP_Error('no_events_found', 'No events found.', array('status' => 404));
    }
    $formatted_posts = array();

    foreach ($events  as $events ) {
      $featured_image_id = get_post_thumbnail_id($events->ID);
      $featured_image_url = '';
      if ($featured_image_id) {
          $featured_image_data = wp_get_attachment_image_src($featured_image_id, 'full');
          if (is_array($featured_image_data)) {
              $featured_image_url = $featured_image_data[0];
          }
      }

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
          
        );
    }
     return $formatted_posts;
  }
}
$allevent= new allevent();

class allcatp{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'allcatp') );
  }
  function allcatp(){
    register_rest_route(
      'Voxel/v1',
      '/allcatp',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request) {
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
                 'icon'=>$category['icon'],
                //'icon'=> $categories['icon'],
                // Add more fields as needed
        );
        
    }

    return $formatted_categories;
}

}
$allcatp = new allcatp();

class pricerange{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'pricerange') );
  }
  function pricerange(){
    register_rest_route(
      'Voxel/v1',
      '/pricerange',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'price'),
      )
    );
  }
  
  function price(){
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
$pricerange =new pricerange();

class social{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'social') );
  }
  function social(){
    register_rest_route(
      'Voxel/v1',
      '/social',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  
  function getall(){
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
$social =new social();

class getcities{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'getcities') );
  }
  function getcities(){
    register_rest_route(
      'Voxel/v1',
      '/getcities',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall(){
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
    $formatted_city[] = array(
        'id' => $continent['id'],
        'name' => $continent['label'],
        'slug' => $continent['slug'],
        
    );

    foreach ($continent['children'] as $city2) {
        $formatted_city[] = array(
            'id' => $city2['id'],
            'name' => $city2['label'],
            'slug' => $city2['slug'],
            'parent_id' => $continent['id'],
        );
    }
}
    return  $formatted_city;
  }
}
$getcities = new getcities();

class getamenities{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'getamenities') );
  }
  function getamenities(){
    register_rest_route(
      'Voxel/v1',
      '/getamenities',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall(){
    $taxonomy = 'amenities';
    $amenities = get_terms(array(
        'taxonomy' => $taxonomy,
        'hide_empty' => false,
        'hierarchical' => true,
    ));
    if (is_wp_error($amenities)) {
      return  $amenities;
     }

    if (empty($amenities)) {
      return new \WP_Error('no_amenities_found', 'No amenities found.', array('status' => 404));
    }
    $formatted_amenities = array();
   
   foreach ($amenities as $amenitie) {
    $formatted_amenities[] = array(
        'id' => $amenitie['id'],
        'name' => $amenitie['label'],
        'slug' => $amenitie['slug'],
        
    );

    foreach ($amenitie['children'] as $amenitie2) {
        $formatted_amenities[] = array(
            'id' => $amenitie2['id'],
            'name' => $amenitie2['label'],
            'slug' => $amenitie2['slug'],
            'parent_id' => $amenitie['id'],
        );
    }
}
    return  $formatted_amenities;
  }
}
$getamenities = new getamenities();

class rastag{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'rastag') );
  }
  function rastag(){
    register_rest_route(
      'Voxel/v1',
      '/rastag',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall(){
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
$rastag= new rastag();

class catplace{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'catplace') );
  }
  function catplace(){
    register_rest_route(
      'Voxel/v1',
      '/catplace/(?P<category_id>\d+)',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall($request) {
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

class category{
  function __construct()
  {
    add_action( 'rest_api_init', array( $this, 'allcat') );
  }
  function allcat(){
    register_rest_route(
      'Voxel/v1',
      '/allcat',
      array(
        'methods' => 'GET',
        'callback' => array($this, 'getall'),
      )
    );
  }
  function getall(){
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

class profileg {
function __construct() {
    add_action('rest_api_init', array($this, 'profileg'));
  
    }

  function profileg() {
      register_rest_route(
          'Voxel/v1',
          '/profileg/(?P<user_id>\d+)',
          array(
              'methods' => 'GET',
              'callback' => array($this, 'getall'),
          )
      );
  }

  public function getall($request) {
      $user_id = $request->get_param('user_id');// Get the user ID from the request
      
      $listings = $this->get_listings_for_user($user_id);

      return rest_ensure_response($listings);
  }

  function get_listings_for_user($user_id) {
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
      $results = $wpdb->get_results( $query );
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

class profilej{
  function __construct() {
    add_action('rest_api_init', array($this, 'profilej'));
  
    }
    function profilej() {
      register_rest_route(
          'Voxel/v1',
          '/profilej/(?P<user_id>\d+)',
          array(
              'methods' => 'GET',
              'callback' => array($this, 'getall'),
          )
      );
    }
    function getall($request) {
      $user_id = $request->get_param('user_id');// Get the user ID from the request
      
      $listings = $this->get_listings_for_user($user_id);

      return rest_ensure_response($listings);
    }
    function get_listings_for_user($user_id) {
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
        $results = $wpdb->get_results( $query );
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
                  'name'=> $result->post_name,
                  // Add more fields as needed
              );
          }
      }
      return $formatted_results;
       
    }
}
$profilej= new profilej();

class profilee{
  function __construct() {
    add_action('rest_api_init', array($this, 'profilee'));
  
    }
    function profilee() {
      register_rest_route(
          'Voxel/v1',
          '/profilee/(?P<user_id>\d+)',
          array(
              'methods' => 'GET',
              'callback' => array($this, 'getall'),
          )
      );
    }
    function getall($request) {
      $user_id = $request->get_param('user_id');// Get the user ID from the request
      
      $listings = $this->get_listings_for_user($user_id);

      return rest_ensure_response($listings);
    }
    function get_listings_for_user($user_id) {
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
        $results = $wpdb->get_results( $query );
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

class postst{
  function __construct() {
    add_action('rest_api_init', array($this, 'postst'));
  }
    function postst() {
      register_rest_route(
          'Voxel/v1',
          '/postst/(?P<id>\d+)',
          array(
              'methods' => 'POST',
              'callback' => array($this, 'changes'),
          )
      );
    }
    
  function changes($request){
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
$postst= new postst();

class deletp{
  function __construct() {
    add_action('rest_api_init', array($this, 'deletp'));
  }
    function deletp() {
      register_rest_route(
          'Voxel/v1',
          '/deletp/(?P<id>\d+)',
          array(
              'methods' => 'DELETE',
              'callback' => array($this, 'delete'),
          )
      );
    }
    function delete($request){
      $id = $request->get_param('id');
      
      $result = wp_delete_post($id, true);
      if ($result === false) {
        return new \WP_Error('failed', 'Failed to delete the post.', array('status' => 500));
      }
      return array('message' => 'Post deleted successfully.');
    }
}
$deletp= new deletp();

class search{
  function __construct() {
    add_action('rest_api_init', array($this, 'search'));
  }
    function search() {
      register_rest_route(
          'Voxel/v1',
          '/search/(?P<query>.*)',
          array(
              'methods' => 'GET',
              'callback' => array($this, 'searchp'),
          )
      );
      register_rest_route(
        'Voxel/v1',
        '/search', // No query parameter
        array(
            'methods' => 'GET',
            'callback' => array($this, 'handle_empty_search'),
        )
    );
    }
    
    function handle_empty_search(){
      if (empty($search_query)) {
        return new \WP_Error('invalid_search', 'Search query cannot be empty.', array('status' => 400));
    }
    }

    function searchp($request){
    $search_query = $request->get_param('query');
    
    if (empty($search_query)) {
        return new \WP_Error('invalid_search', 'Search query cannot be empty.', array('status' => 400));
    }

    // Perform your search logic here
    $search_results = $this->your_custom_search_function($search_query);

    // Return the search results
    return rest_ensure_response($search_results);
}

function your_custom_search_function($search_query) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'posts'; // Get the table name with prefix

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
    ", '%' . $wpdb->esc_like( $search_query ) . '%', '%' . $wpdb->esc_like( $search_query ) . '%', '%' . $wpdb->esc_like( $search_query ) . '%');

    // Execute query
    $results = $wpdb->get_results($sql);

    // Process results
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

    return $formatted_results;
}
}
$search = new search();

class searchpl {
  function __construct() {
      add_action('rest_api_init', array($this, 'searchpl'));
  }

  function searchpl() {
      register_rest_route(
          'Voxel/v1',
          '/searchpl/(?P<params>.+)',
          array(
              'methods' => 'GET',
              'callback' => array($this, 'getall'),
          )
      );
  }

  function format_param($param) {
      // Remove special characters
      $param = preg_replace('/[^a-zA-Z0-9-]/', '', $param);
      
      // Convert to lowercase and replace spaces with hyphens
      $param = strtolower(str_replace(' ', '-', $param));

      return $param;
  }

  function getall($request) {
      $params = $request->get_param('params');
      $parameters = explode('/', $params);

      $cities = array();
      $categories = array();
      $amenities = array();
      
      foreach ($parameters as $param) {
    
          if (!empty($param)) {
              if (taxonomy_exists('city') && term_exists($param, 'city')) {
                  $cities[] = $param;
              } elseif (taxonomy_exists('places_category') && term_exists($param, 'places_category')) {
                  $categories[] = $param;
              } elseif (taxonomy_exists('amenities') && term_exists($param, 'amenities')) {
                  $amenities[] = $param;
              }
          }
      }
      // Build the query arguments based on the provided parameters
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
              'field' => 'slug',
              'terms' => $cities,
              'operator' => 'IN',
          );
      }

      if (!empty($categories)) {
          $args['tax_query'][] = array(
              'taxonomy' => 'places_category', 
              'field' => 'slug',
              'terms' => $categories,
              'operator' => 'IN',
          );
      }

      if (!empty($amenities)) {
          $args['tax_query'][] = array(
              'taxonomy' => 'amenities',
              'field' => 'slug',
              'terms' => $amenities,
              'operator' => 'IN',
          );
      }

      // Perform the query
      $query = new \WP_Query($args);

      // Prepare results
      $results = array();
      // var_dump($query->request);
      // die;
      if ($query->have_posts()) {
          while ($query->have_posts()) {
              $query->the_post();
               $post_data = array(
                  'id' => get_the_ID(),
                  'title' => get_the_title(),
                  );
                  $thumbnail_id = get_post_thumbnail_id();
                  $thumbnail = wp_get_attachment_image_src($thumbnail_id, 'thumbnail');
                  if ($thumbnail) {
                      $post_data['thumbnail'] = $thumbnail[0];
                  }
                  $logo_id = get_post_meta(get_the_ID(), 'logo', true);
                  if ($logo_id) {
                      $logo = wp_get_attachment_image_src($logo_id, 'full');
                      if ($logo) {
                          $post_data['logo'] = $logo[0];
                      }
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
}

$searchpl = new searchpl();