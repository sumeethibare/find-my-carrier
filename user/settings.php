<?php
require_once "../config/db.php";
protect();

$username     = $_SESSION['username'] ?? '';
$upload_error = '';

// Fetch user details
$stmt = $conn->prepare("SELECT email, location, dob, profile_pic, institute, stream, branch, gender, farmer_family FROM users WHERE username=?");
$stmt->bind_param("s", $username);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();

// Define settings sections dynamically
$settings_sections = [
  [
    'title'       => 'Profile',
    'description' => 'Update your personal information',
    'action'      => [
      'label'   => 'Edit Profile',
      'type'    => 'button',
      'onclick' => "toggleModal('profileModal')"
    ],
  ],
  [
    'title'       => 'Security',
    'description' => 'Manage your account security',
    'action'      => [
      'label'   => 'Change Password',
      'type'    => 'button',
      'onclick' => "toggleModal('passwordModal')"
    ],
  ],
  [
    'title'       => 'Account',
    'description' => 'Manage your account settings',
    'action'      => [
      'label' => 'Logout',
      'type'  => 'link',
      'href'  => 'logout.php'
    ],
  ],
];

// Define profile fields dynamically (including new fields)
$profile_fields = [
  [
    'name'     => 'email',
    'label'    => 'Email',
    'type'     => 'email',
    'value'    => htmlspecialchars($user['email'] ?? ''),
    'required' => true,
  ],
  [
    'name'     => 'location',
    'label'    => 'Location',
    'type'     => 'text',
    'value'    => htmlspecialchars($user['location'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'dob',
    'label'    => 'Date of Birth',
    'type'     => 'date',
    'value'    => htmlspecialchars($user['dob'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'gender',
    'label'    => 'Gender',
    'type'     => 'radio',
    'options'  => ['Male', 'Female', 'Other'],
    'value'    => htmlspecialchars($user['gender'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'farmer_family',
    'label'    => 'Are you from a farmer family?',
    'type'     => 'radio',
    'options'  => ['Yes', 'No'],
    'value'    => htmlspecialchars($user['farmer_family'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'institute',
    'label'    => 'Institute',
    'type'     => 'text',
    'value'    => htmlspecialchars($user['institute'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'stream',
    'label'    => 'Stream',
    'type'     => 'select',
    'options'  => ['Medical', 'Engineering'],
    'value'    => htmlspecialchars($user['stream'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'branch',
    'label'    => 'Branch',
    'type'     => 'select',
    'options'  => [
      'Medical'     => [
        'MBBS','BDS','BAMS','BHMS','BUMS','BNYS','BVSc & AH',
        'BPT','B.Sc Nursing','BMLT','B.Pharm','BOT','BASLP','Paramedical Courses'
      ],
      'Engineering' => [
        'Computer Science and Engineering','Information Technology','Electronics and Communication Engineering',
        'Electrical Engineering','Mechanical Engineering','Civil Engineering','Chemical Engineering',
        'Biotechnology','Aerospace Engineering','Automobile Engineering','Environmental Engineering',
        'Petroleum Engineering','Instrumentation Engineering','Marine Engineering','Robotics and Automation',
        'Mechatronics Engineering','Agricultural Engineering','Mining Engineering','Textile Engineering',
        'Industrial Engineering','Biomedical Engineering','Data Science and AI/ML',
        'Cybersecurity Engineering','Food Technology','Metallurgical Engineering'
      ],
    ],
    'value'    => htmlspecialchars($user['branch'] ?? ''),
    'required' => false,
  ],
  [
    'name'     => 'profile_pic',
    'label'    => 'Profile Picture',
    'type'     => 'file',
    'accept'   => 'image/jpeg,image/png',
    'value'    => $user['profile_pic']
      ? 'data:image/jpeg;base64,' . base64_encode($user['profile_pic'])
      : 'https://via.placeholder.com/48',
    'required' => false,
  ],
];

// Handle POST updates
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Update email, location, dob
  foreach (['email','location','dob'] as $field) {
    if (isset($_POST["update_$field"])) {
      $value = filter_var($_POST[$field], FILTER_SANITIZE_STRING) ?: null;
      $stmt  = $conn->prepare("UPDATE users SET $field=? WHERE username=?");
      $stmt->bind_param("ss", $value, $username);
      $stmt->execute();
      header("Location: settings.php");
      exit;
    }
  }

  // Update gender and farmer_family fields
  foreach (['gender','farmer_family'] as $field) {
    if (isset($_POST["update_$field"])) {
      $value = filter_var($_POST[$field], FILTER_SANITIZE_STRING) ?: null;
      $stmt  = $conn->prepare("UPDATE users SET $field=? WHERE username=?");
      $stmt->bind_param("ss", $value, $username);
      $stmt->execute();
      header("Location: settings.php");
      exit;
    }
  }

  // Update newly added fields: institute, stream, branch
  foreach (['institute','stream','branch'] as $field) {
    if (isset($_POST["update_$field"])) {
      $value = filter_var($_POST[$field], FILTER_SANITIZE_STRING) ?: null;
      $stmt  = $conn->prepare("UPDATE users SET $field=? WHERE username=?");
      $stmt->bind_param("ss", $value, $username);
      $stmt->execute();
      header("Location: settings.php");
      exit;
    }
  }

  // Update profile picture
  if (isset($_POST['update_profile_pic'])) {
    if (!empty($_FILES['profile_pic']['tmp_name'])) {
      $file         = $_FILES['profile_pic'];
      $allowed      = ['image/jpeg','image/png'];
      $max_size     = 2 * 1024 * 1024;
      if (in_array($file['type'],$allowed) && $file['size'] <= $max_size) {
        $profile_pic = file_get_contents($file['tmp_name']);
      } else {
        $upload_error = "Invalid file type or size. Use JPEG/PNG, max 2MB.";
      }
    }
    if (!$upload_error) {
      $stmt = $conn->prepare("UPDATE users SET profile_pic=? WHERE username=?");
      $stmt->bind_param("ss",$profile_pic,$username);
      $stmt->execute();
      header("Location: settings.php");
      exit;
    }
  }

  // Update password
  if (isset($_POST['update_password'])) {
    $old = $_POST['old_password'];
    $new = $_POST['new_password'];
    $stmt = $conn->prepare("SELECT password FROM users WHERE username=?");
    $stmt->bind_param("s",$username);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    if (password_verify($old,$result['password'])) {
      $hashed = password_hash($new,PASSWORD_DEFAULT);
      $stmt   = $conn->prepare("UPDATE users SET password=? WHERE username=?");
      $stmt->bind_param("ss",$hashed,$username);
      $stmt->execute();
      header("Location: settings.php");
      exit;
    } else {
      $error = "Invalid current password.";
    }
  }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <?php get_head("Settings - Find My Career"); ?>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root { --transition-speed: 0.3s; }
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 50;
      transition: opacity var(--transition-speed) ease;
    }
    .modal.active {
      display: flex;
      opacity: 1;
    }
    .modal-bg {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.4);
      backdrop-filter: blur(4px);
    }
    .modal-content {
      position: relative;
      background: white;
      margin: auto;
      transition: transform var(--transition-speed) ease, opacity var(--transition-speed) ease;
    }
    .profile-pic { transition: transform 0.2s ease; }
    .profile-pic:hover { transform: scale(1.05); }
    button { position: relative; overflow: hidden; }
    button::after {
      content: '';
      position: absolute; top: 50%; left: 50%;
      width: 0; height: 0;
      background: rgba(255,255,255,0.2);
      border-radius: 50%;
      transform: translate(-50%,-50%);
      transition: width 0.3s ease, height 0.3s ease;
    }
    button:hover::after { width:200%; height:200%; }
    .radio-group { display: flex; gap: 1rem; }
    .radio-option { display: flex; align-items: center; gap: 0.5rem; }

    /* Mobile styles */
    @media (max-width: 767px) {
      #profileModal .modal-content {
        width: 100%;
        height: 70vh;
        border-radius: 1rem 1rem 0 0;
        position: fixed;
        bottom: 0;
        left: 0;
      }
    }

    /* Desktop styles */
    @media (min-width: 768px) {
      #profileModal .modal-content {
        width: 80%;
        max-width: 800px;
        height: 80vh;
        border-radius: 0.5rem;
      }

      #passwordModal .modal-content {
        width: 100%;
        max-width: 400px;
        border-radius: 0.5rem;
      }
    }
  </style>
</head>
<body class="min-h-screen flex flex-col text-gray-800 bg-white">
  <div class="flex flex-col md:flex-row w-full">
    <!-- Sidebar -->
    <?php include("./includes/sidebar.php"); ?>

    <main class="flex-1 p-4 md:p-6 w-full overflow-y-auto">
      <h2 class="text-3xl text-gray-800">Settings</h2>
      <p class="text-gray-600 text-sm mt-1">Manage your profile and account security</p>

      <div class="bg-zinc-50 rounded-3xl p-4 mt-6">
        <?php foreach ($settings_sections as $index => $section): ?>
          <div class="<?php echo $index < count($settings_sections)-1 ? 'border-b border-gray-200 pb-4 mb-4' : ''; ?>">
            <div class="flex justify-between lg:items-center flex-col lg:flex-row">
              <div>
                <h3 class="text-lg font-regular text-gray-800"><?php echo htmlspecialchars($section['title']); ?></h3>
                <p class="text-sm text-gray-500"><?php echo htmlspecialchars($section['description']); ?></p>
              </div>
              <div class="flex justify-between items-center mt-2">
                <?php if ($section['action']['type'] === 'button'): ?>
                  <button onclick="<?php echo htmlspecialchars($section['action']['onclick']); ?>"
                          class="bg-zinc-600 text-white px-4 py-2 rounded-full text-sm hover:bg-blue-700 my-2">
                    <?php echo htmlspecialchars($section['action']['label']); ?>
                  </button>
                <?php else: ?>
                  <a href="<?php echo htmlspecialchars($section['action']['href']); ?>"
                     class="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700">
                    <?php echo htmlspecialchars($section['action']['label']); ?>
                  </a>
                <?php endif; ?>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </main>
    <?php include("includes/bottom.php"); ?>
  </div>

  <!-- Profile Modal -->
  <div id="profileModal" class="modal">
    <div class="modal-bg" onclick="toggleModal('profileModal')"></div>
    <div class="modal-content">
      <div class="p-4 sm:p-6 sticky top-0 bg-white z-10 md:flex md:justify-between md:items-center">
        <div>
          <h2 class="text-xl font-semibold text-gray-800">Edit Profile</h2>
          <p class="text-sm text-gray-500">Update your personal information</p>
        </div>
        <button onclick="toggleModal('profileModal')" class="text-gray-500 hover:text-gray-700">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>
      <div class="p-4 sm:p-6 overflow-y-auto">
        <?php if ($upload_error): ?>
          <p class="text-red-600 text-sm mb-2"><?php echo htmlspecialchars($upload_error); ?></p>
        <?php endif; ?>

        <div class="mt-6 border-t border-gray-100">
          <dl class="divide-y divide-gray-100">
            <?php foreach ($profile_fields as $field): ?>
              <form method="POST" <?php echo $field['type']==='file'?'enctype="multipart/form-data"':''; ?>>
                <input type="hidden" name="update_<?php echo htmlspecialchars($field['name']); ?>" value="1">
                <div class="py-4 sm:grid sm:grid-cols-3 sm:gap-4">
                  <dt class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($field['label']); ?></dt>
                  <dd class="mt-1 text-sm text-gray-700 sm:col-span-2 sm:mt-0 flex gap-2 items-center">
                    <?php if ($field['type'] === 'file'): ?>
                      <img src="<?php echo htmlspecialchars($field['value']); ?>"
                           class="profile-pic w-12 h-12 rounded-full border border-gray-200">
                      <input type="file" name="<?php echo htmlspecialchars($field['name']); ?>"
                             id="<?php echo htmlspecialchars($field['name']); ?>Input"
                             accept="<?php echo htmlspecialchars($field['accept']); ?>"
                             class="text-sm text-gray-500">
                    <?php elseif ($field['type'] === 'select'): ?>
                      <select name="<?php echo htmlspecialchars($field['name']); ?>"
                              id="<?php echo htmlspecialchars($field['name']); ?>Select"
                              onchange="<?php echo $field['name']==='stream'?'handleStreamChange(this)':''; ?>"
                              class="w-full p-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-1 focus:ring-blue-500">
                        <option value="">Select...</option>
                        <?php if ($field['name'] === 'branch'): ?>
                          <?php
                            $branches = $field['options'][$user['stream'] ?? ''] ?? [];
                            foreach ($branches as $opt):
                              $sel = $opt === $field['value'] ? 'selected' : '';
                          ?>
                            <option value="<?php echo $opt;?>" <?php echo $sel;?>><?php echo $opt;?></option>
                          <?php endforeach;?>
                        <?php else: ?>
                          <?php foreach ($field['options'] as $opt):
                            $sel = $opt === $field['value'] ? 'selected' : '';
                          ?>
                            <option value="<?php echo $opt;?>" <?php echo $sel;?>><?php echo $opt;?></option>
                          <?php endforeach;?>
                        <?php endif;?>
                      </select>
                    <?php elseif ($field['type'] === 'radio'): ?>
                      <div class="radio-group">
                        <?php foreach ($field['options'] as $option): ?>
                          <div class="radio-option">
                            <input type="radio"
                                   name="<?php echo htmlspecialchars($field['name']); ?>"
                                   id="<?php echo htmlspecialchars($field['name']) . '_' . htmlspecialchars($option); ?>"
                                   value="<?php echo htmlspecialchars($option); ?>"
                                   <?php echo $option === $field['value'] ? 'checked' : ''; ?>
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300">
                            <label for="<?php echo htmlspecialchars($field['name']) . '_' . htmlspecialchars($option); ?>"
                                   class="text-sm text-gray-700">
                              <?php echo htmlspecialchars($option); ?>
                            </label>
                          </div>
                        <?php endforeach; ?>
                      </div>
                    <?php else: ?>
                      <input type="<?php echo htmlspecialchars($field['type']); ?>"
                             name="<?php echo htmlspecialchars($field['name']); ?>"
                             value="<?php echo htmlspecialchars($field['value']);?>"
                             <?php echo $field['required']?'required':'';?>
                             class="w-full p-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-1 focus:ring-blue-500">
                    <?php endif; ?>
                    <button type="submit"
                            class="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                      <?php echo $field['type']==='file'?'Upload':'Update';?>
                    </button>
                  </dd>
                </div>
              </form>
            <?php endforeach; ?>
          </dl>
        </div>
      </div>
    </div>
  </div>

  <!-- Password Modal -->
  <div id="passwordModal" class="modal">
    <div class="modal-bg" onclick="toggleModal('passwordModal')"></div>
    <div class="modal-content">
      <div class="p-4 sm:p-6">
        <h2 class="text-xl font-semibold text-gray-800">Change Password</h2>
        <?php if (isset($error)): ?>
          <p class="text-red-600 text-sm mb-2"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form method="POST" class="space-y-4">
          <input type="hidden" name="update_password" value="1">
          <div>
            <label class="text-sm font-medium text-gray-700">Current Password</label>
            <input type="password" name="old_password" required
                   class="w-full p-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-1 focus:ring-blue-500">
          </div>
          <div>
            <label class="text-sm font-medium text-gray-700">New Password</label>
            <input type="password" name="new_password" required
                   class="w-full p-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-1 focus:ring-blue-500">
          </div>
          <div class="flex gap-2">
            <button type="submit"
                    class="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
              Change
            </button>
            <button type="button" onclick="toggleModal('passwordModal')"
                    class="bg-gray-200 text-gray-800 px-4 py-2 rounded-md hover:bg-gray-300">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <script>
  // Ensure DOM is fully loaded before attaching event listeners
  document.addEventListener('DOMContentLoaded', () => {
    // Toggle modal visibility
    function toggleModal(id) {
      const modal = document.getElementById(id);
      if (modal) {
        modal.classList.toggle('active');
        // Prevent background scrolling when modal is open
        document.body.style.overflow = modal.classList.contains('active') ? 'hidden' : '';
      }
    }

    // Close modal when clicking outside content
    document.querySelectorAll('.modal-bg').forEach(bg => {
      bg.addEventListener('click', function () {
        const modal = this.closest('.modal');
        modal.classList.remove('active');
        document.body.style.overflow = '';
      });
    });

    // Close modal with Escape key
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
          modal.classList.remove('active');
          document.body.style.overflow = '';
        });
      }
    });

    // Handle stream => branch logic
    function handleStreamChange(select, selectedBranch = '') {
      const stream = select.value;
      const branchSelect = document.getElementById('branchSelect');
      if (!branchSelect) return;

      const medical = <?php echo json_encode($profile_fields[7]['options']['Medical']); ?>;
      const engineering = <?php echo json_encode($profile_fields[7]['options']['Engineering']); ?>;

      let options = '<option value="">Select...</option>';
      const branches = stream === 'Medical' ? medical : stream === 'Engineering' ? engineering : [];

      branches.forEach(branch => {
        const selected = branch === selectedBranch ? 'selected' : '';
        options += `<option value="${branch}" ${selected}>${branch}</option>`;
      });

      branchSelect.innerHTML = options;
    }

    // Set initial stream => branch
    const streamSelect = document.getElementById('streamSelect');
    const savedBranch = "<?php echo addslashes($user['branch'] ?? ''); ?>";
    if (streamSelect) {
      handleStreamChange(streamSelect, savedBranch);
    }

    // Expose toggleModal to global scope for inline onclick
    window.toggleModal = toggleModal;
  });
</script>

</body>
</html>
