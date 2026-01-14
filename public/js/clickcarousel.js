document.addEventListener("DOMContentLoaded", () => {
    const clicked = document.querySelector("#heroCarousel");
    if (clicked) {
        clicked.addEventListener("click", (e) => {
            if (!e.target.closest("button, a")) {
                window.location.href = "/products";
            }
        });
    }
});
