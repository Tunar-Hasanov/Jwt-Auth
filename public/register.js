document.getElementById('registerForm').addEventListener('submit', async (event) => {
    event.preventDefault();
  
    const userId = document.getElementById('userId').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
  
    const response = await fetch('/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ userId, email, password })
    });
  
    if (response.ok) {
      window.location.href = '/auth/login';
    } else {
      alert('Registration failed');
    }
  });
  