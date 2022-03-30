# AESCHIPER

example 

$secretKey = 'AjGfpbbQmU7EAnkJ';
$text = 'text yg akan di encode atau di decode';

$encrypted = AesCipher::encrypt($secretKey, $text);
$decrypted = AesCipher::decrypt($secretKey, $encrypted);
