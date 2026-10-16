<?php
// A file read with no include in it.
//
// The wrapper chain manufactures PHP source in the stream and depends on the
// application parsing it. `file_get_contents` does not parse - it hands the
// bytes back as a string - so this endpoint is where the chain can never work
// while `php://filter/convert.base64-encode/resource=...` works perfectly well.
//
// That pair is the shape worth having in the lab: "the read worked and the chain
// did not" is a conclusion an operator will otherwise read as "the target cannot
// execute code", and it means nothing of the kind. Offered as a GET and as a
// POST field, because where the value lands decides which one is needed.
$file = $_GET['file'] ?? '';
if ($file === '' && isset($_POST['file'])) {
    $file = $_POST['file'];
}
if ($file === '') {
    echo "no file given\n";
    exit;
}
// The path is what it is: this endpoint exists to be a read sink, not to be safe.
echo @file_get_contents($file);
