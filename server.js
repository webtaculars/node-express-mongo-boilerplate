var express = require('express');
var bodyParser = require('body-parser');
var morgan = require('morgan');
var config = require('./config');
var mongoose = require('mongoose');

var app = express();

var http = require('http').Server(app);

mongoose.connect(config.database, function(err){
  if(err){
    console.log(err);
  }
  else {
    console.log('DB connected')
  }
});

app.use(bodyParser.urlencoded({ extended:true }));
app.use(bodyParser.json());
app.use(morgan('dev'));

var api = require('./app/routes/api')(app, express);
app.use('/api', api);

http.listen(config.port, function(err){
  if(err) {
    console.log(err);
  } else {
    console.log('Listening on port 8080');
  }
});
