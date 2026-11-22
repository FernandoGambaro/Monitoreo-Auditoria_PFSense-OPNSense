</div> <!-- Cierre .main-content-wrapper -->
</div> <!-- Cierre .app-wrapper -->

<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebarMenu');
    const btnAbrir = document.getElementById('btnAbrirSidebar');
    const btnCerrar = document.getElementById('btnCerrarSidebar');

    if (btnAbrir && sidebar) {
        btnAbrir.addEventListener('click', () => sidebar.classList.add('show'));
    }
    if (btnCerrar && sidebar) {
        btnCerrar.addEventListener('click', () => sidebar.classList.remove('show'));
    }
});
</script>
</body>
</html>
