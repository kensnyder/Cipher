<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title></title>
		<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
    </head>
    <body>
		convert to base <select name="base">
			<option value="">(binary)</option>
			<?php foreach (range(2,63) as $base) { ?>
				<option value="<?php echo $base?>"<?php echo ($base == @$_REQUEST['options']['base']) ? ' selected="selected"' : ''?>><?php echo $base?></option>
			<?php } ?>
			<option value="64"<?php !@$_REQUEST['options']['base'] ? ' selected="selected"' : '' ?>>64</option>
		</select>
		<br />
		<textarea id="in" cols="60" rows="20"></textarea>
		<input type="button" value="Encrypt" />
		<textarea id="out" cols="60" rows="20"></textarea>
		<script>
			$('input').click(function() {
				var options = {
					base: $('[name=base]').val()
				}
				$.ajax({
					url: 'run.php',
					data: {
						subject: $('#in').val(),
						method: 'encrypt',
						options: options
					},
					success: function(out) {
						$('#out').val(out);
					}
				})
			})
		</script>
    </body>
</html>
