<?php
	require_once('xtea.php');
	$salt = "dave";
	$xtea = new xtea($salt);
	if(isset($_POST['btn_enc'])){
		$cont = file_get_contents($_FILES['raw_file']['tmp_name']);
		$file = basename($_FILES["raw_file"]["name"]);
		$name = pathinfo($file,PATHINFO_FILENAME);
		$ex =  pathinfo($file,PATHINFO_EXTENSION);
		$enc_cont = $xtea->encrypt($cont);
		$file = fopen($xtea->encrypt("$name").".".$ex,"w");
		fwrite($file,$enc_cont);
		fclose($file);
		echo '<script>alert("File has been successfully encrypted!")</script>';
	}
	else if(isset($_POST['btn_dec'])){
		$cont = file_get_contents($_FILES['enc_file']['tmp_name']);
		$file = basename($_FILES["enc_file"]["name"]);
		$name = pathinfo($file,PATHINFO_FILENAME);
		$ex =  pathinfo($file,PATHINFO_EXTENSION);
		$dec_cont = $xtea->decrypt($cont);
		$file = fopen($xtea->decrypt("$name").".".$ex,"w");
		fwrite($file,$dec_cont);
		fclose($file);
		echo '<script>alert("File has been successfully decrypted!")</script>';
	}
?>
<html>
	<head>
		<title>PHP encrypt/decrypt file</title>
	</head>
	<body>
		<h3>Both the file name and it's contents will be encrypted/decrypted.</h3>
		<fieldset>
			<legend>Encrypt File</legend>
			<form method = "post" action = "<?php echo $_SERVER['PHP_SELF'];?>" enctype="multipart/form-data">
				<input type = "file" name = "raw_file">
				<button name = "btn_enc">Submit</button>
			</form>
		</fieldset>
		<fieldset>
			<legend>Decrypt File</legend>
			<form method = "post" action = "<?php echo $_SERVER['PHP_SELF'];?>" enctype="multipart/form-data">
				<input type = "file" name = "enc_file">
				<button name = "btn_dec">Submit</button>
			</form>
		</fieldset>
	</body>
</html>