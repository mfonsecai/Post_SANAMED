document.addEventListener("DOMContentLoaded", function() {
    var puzzle = document.getElementById('puzzle');
    var pieces = document.getElementsByClassName('piece');

    // Mezclar piezas al cargar la página
    shufflePieces();

    // Función para mezclar las piezas
    function shufflePieces() {
        for (var i = 0; i < pieces.length; i++) {
            var newX = Math.floor(Math.random() * (puzzle.offsetWidth - pieces[i].offsetWidth));
            var newY = Math.floor(Math.random() * (puzzle.offsetHeight - pieces[i].offsetHeight));
            pieces[i].style.left = newX + 'px';
            pieces[i].style.top = newY + 'px';
        }
    }

    // Agrega más funcionalidades según sea necesario
});
