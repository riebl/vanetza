document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll("table").forEach(function(table) {
        table.classList.add("docutils");
    });
    document.querySelectorAll("td").forEach(function(cell) {
        if (cell.innerText.length > 40) {
            cell.style.whiteSpace = "normal";
        }
    });
});
