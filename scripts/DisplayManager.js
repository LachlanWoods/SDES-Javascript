var sharedKey;
var plaintext;

$( document ).ready(function() {
    Run();

    $(".RestartButton").click(function() {
      Run();
    });
});

function Run(){
  sharedKey = GenerateRandomBits(10);
  plaintext  = GenerateRandomBits(8);
  $(".SharedKey").text("Shared Key (10 bits): " + sharedKey.join(""));
  $(".Plaintext").text("Plaintext block (8 bits): " + plaintext.join(""));
  Encrypt(plaintext, sharedKey)
  $(".Roundkey1").text("Roundkey 1 (8 bits): " + roundKey1.join(""));
  $(".Roundkey2").text("Roundkey 2 (8 bits): " + roundKey2.join(""));
  $(".Ciphertext").text("Ciphertext (8 bits): " + ciphertext.join(""));
}
