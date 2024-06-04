 document.addEventListener('click', function (event) {
                const submenu = document.querySelector('.submenu');
                // Check if the clicked element is an element with the class .submenu or if it is a direct descendant of the .submenu element.
                if (!event.target.matches('.submenuItem') && !event.target.matches('.submenuItem span') && !submenu.contains(event.target)) {
                  // Rimuovi la classe "showMenuSub" dall'elemento .submenu se presente
                  submenu.classList.remove('showMenuSub');
                }
              });
              var currentPageURL = window.location.pathname;

                  // Search for the menu item that corresponds to the URL of the current page and add the class 'currentMenuSelected'.
                  $(".menuList li a").each(function() {
                      if ($(this).attr("href") === currentPageURL) {
                          //console.log('found');
                          $(this).addClass("currentMenuSelected");

                          if ($(this).parent().parent().hasClass("subMenuList")) {
                              console.log('e si');
                              $(this).parent().closest("li.submenuItem").addClass("currentMenuSelectedLi");
                          }

                          return false; // Exit the loop once the corresponding element is found
                      }
                  });
