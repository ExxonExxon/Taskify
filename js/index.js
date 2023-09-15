    const statistics = document.querySelectorAll('.statistic');
    let currentStatisticIndex = 0;

    function updateStatistics() {
      statistics[currentStatisticIndex].classList.remove('active');
      currentStatisticIndex = (currentStatisticIndex + 1) % statistics.length;
      statistics[currentStatisticIndex].classList.add('active');
    }

    // Update statistics every 3 seconds
    setInterval(updateStatistics, 3000);

    // Initialize the first statistic
    statistics[currentStatisticIndex].classList.add('active');

    // Tron-ify the Intersection Observer to animate features and Recognizer
    const recognizerCards = document.querySelectorAll('.feature-card');
    const recognizerFooter = document.querySelector('footer');

    const tronOptions = {
      threshold: 0.2
    };

    const animateRecognizer = (entries, observer) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.animation = 'fadeInUp 1s forwards';
          observer.unobserve(entry.target);
        }
      });
    };

    const recognizerFooterObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.animation = 'fadeInUp 1s forwards';
        }
      });
    }, tronOptions);

    recognizerCards.forEach(card => {
      const recognizerObserver = new IntersectionObserver(animateRecognizer, tronOptions);
      recognizerObserver.observe(card);
    });

    recognizerFooterObserver.observe(recognizerFooter);

    function sendToDownloads() {
        window.location.href = 'http://127.0.0.1/downloads'
    }