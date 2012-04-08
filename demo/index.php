<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title></title>
		<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
    </head>
    <body>
		convert to base <select name="base">
			<option value="">(no conversion)</option>
			<?php foreach (range(2,64) as $base) { ?>
				<option value="<?php echo $base?>"<?php echo ($base == @$_REQUEST['options']['base']) ? ' selected=selected' : ''?>><?php echo $base?></option>
			<?php } ?>
		</select>
		<br />
		<textarea id="in" cols="60"></textarea>
		<input type="button" value="Encrypt" />
		<textarea id="out" cols="60"></textarea>
		<script>
			$('input').click(function() {
				$.ajax({
					url: 'run.php',
					data: {
						subject: $('#in').val(),
						method: 'encrypt',
						options: {
							base: $('[name=base]').val()
						}
					},
					success: function(out) {
						$('#out').val(out);
					}
				})
			})
		</script>
    </body>
</html>
