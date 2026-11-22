<?php

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container mt-4">

<div class="card">

<div class="card-header">

Importar Log Firewall

</div>

<div class="card-body">

<form
    action="process_import.php"
    method="post"
    enctype="multipart/form-data">

<div class="form-group">

<label>

Seleccione archivo Excel

</label>

<input
    type="file"
    name="archivo"
    class="form-control"
    accept=".xlsx,.xls"
    required>

</div>

<button
    type="submit"
    class="btn btn-primary">

Importar

</button>

</form>

</div>

</div>

</div>

<?php include 'views/footer.php'; ?>