const successPercentage = countGood / countTotal * 100;
        let failurePercentage = countBad / countTotal * 100;
        let informationalPercentage = countWarning / countTotal * 100;
        const data = [{
            data: [successPercentage, failurePercentage, informationalPercentage],
            backgroundColor: [
                "#4ecb71",
                "#ff5c5c",
                "#f5e230",
            ],
            borderColor: "#fff"
        }];

        const options = {
            tooltips: {
                enabled: false
            },
            plugins: {
                datalabels: {
                    formatter: (value, ctx) => {
                        let sum = 0;
                        let dataArr = ctx.chart.data.datasets[0].data;
                        dataArr.map(data => {
                            sum += data;
                        });
                        return (value * 100 / sum).toFixed(2) + "%";
                    },
                    color: '#fff',
                },
                title: {
                    display: true,
                    text: 'Score'
                }
            },
        };

        const ctx = document.getElementById("chart1").getContext('2d');
        const myChart = new Chart(ctx, {
            type: 'pie',
            data: {
                datasets: data
            },
            options: options
        });

        document.getElementById('vulnerable-count').innerHTML = countBad;
        document.getElementById('good-count').innerHTML = countGood;
        document.getElementById('warning-count').innerHTML = countWarning;
      