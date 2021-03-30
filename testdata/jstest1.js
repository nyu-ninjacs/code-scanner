const express = require('express')

const app = express()

app.get('/', (req, res) => {
    // (select\s.*from|delete\s+from|insert\s+into\s.*values|update\s.*set).*req\..*;
    query = "SELECT * FROM sometable Where id='" + req.body['id'] + "'";
    eval(req.body)
    res.status(200).send({
        success: 'true',
        message: 'horus\'s intentionally vulnerable API!',
    })
  });

const PORT = 8888;
  
app.listen(PORT, () => {
console.log('start running')
});