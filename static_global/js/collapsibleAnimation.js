const coll = document.getElementsByClassName("collapsible");
        let i;

        for (i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function () {
                this.classList.toggle("active");
                const content = this.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            });
        }
        $('.accordion-button').click(function () {
            $(this).find('.bi').toggleClass('rotate');
        });
        $('.list-group-item').click(function () {
            $(this).find('.bi').toggleClass('rotate');
        });
