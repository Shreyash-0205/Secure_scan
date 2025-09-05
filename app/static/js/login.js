document.getElementById('loginForm').addEventListener('submit', function (e) {
  e.preventDefault(); // stop normal form submission

  const username = document.getElementById('Email').value;
  const password = document.getElementById('Password').value;

  console.log(username)
  console.log(password)

});