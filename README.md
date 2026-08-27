صفحة الوليد

<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>الوليد</title>

  <style>
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #080808;
      color: white;
      text-align: center;
    }

    .box {
      max-width: 500px;
      margin: 100px auto;
      padding: 30px;
      background: #151515;
      border-radius: 20px;
      box-shadow: 0 0 25px #000;
    }

    h1 {
      color: #00ff66;
    }

    button {
      padding: 14px 25px;
      border: 0;
      border-radius: 10px;
      background: #00c853;
      color: white;
      font-size: 18px;
      cursor: pointer;
    }

    #message {
      display: none;
      margin-top: 25px;
      color: #ff4444;
      font-size: 20px;
    }
  </style>
</head>

<body>

  <div class="box">
    <h1>مرحبًا بك</h1>
    <p>هذه الصفحة الخاصة بالوليد</p>

    <button onclick="showMessage()">اضغط هنا</button>

    <div id="message">
      😂 ودعت الملاعب صورك وفديوهات عندي الحين 🙂‍↕️ 
    </div>
  </div>

  <script>
    function showMessage() {
      document.getElementById("message").style.display = "block";
    }
  </script>

</body>
</html>
