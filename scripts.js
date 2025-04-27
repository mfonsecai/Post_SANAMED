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


document.getElementById('agregar-gratitud').addEventListener('click', function() {
    const gratitud = document.getElementById('input-gratitud').value.trim();
    const idUsuario = 1;  // Asegúrate de usar el id del usuario logueado

    if (gratitud !== "") {
        fetch('http://localhost:5000/agregar_gratitud', {  // Asegúrate de usar el puerto correcto
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                gratitud: gratitud,
                id_usuario: idUsuario
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                alert(data.message);
                agregarFlorAlJardin(gratitud);
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    } else {
        alert('Por favor, escribe algo por lo que estés agradecido.');
    }
});
