const express = require('express')
const expat = require('node-expat');
const app = express()

require("crypto")
    .createHash("sha1")
    .update("Man oh man do I love node!")
    .digest("hex");

app.get('/', (req, res) => {
    query = "SELECT * FROM sometable Where id='" + req.body['id'] + "'";
    eval(req.body)
    require('js-yaml').load(req.body)
    res.set('x-xss-protection', 0);
    res.status(200).send({
        success: 'true',
        message: 'horus\'s intentionally vulnerable API!',
    })
});

app.post('/login', function (req, res) {
    User.findOne({ 'email': req.body.email, 'password': req.body.password }, function (err, data) {
        if (err) {
            res.send(err);
        } else if (data) {
            res.send('User Login Successful');
        } else {
            res.send('Wrong Username Password Combination');
        }
    })
});

app.get('/parse', async (req, res) => {
    var parser = new expat.Parser('UTF-8')

    parser.parse(req.body)
    res.send('Hello World!')
})

const PORT = 8888;
  
app.listen(PORT, () => {
console.log('start running')
});