
app.post('/smth', function (req, res) {
    var query = {};
    
    query['email'] = req.body.email;
    User.findOne(query, function (err, data) {
        if (err) {
            res.send(err);
        } else if (data) {
            res.send('User Login Successful');
        } else {
            res.send('Wrong Username Password Combination');
        }
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

var MongoClient = require('mongodb').MongoClient;
// mongo js injection https://lockmedown.com/securing-node-js-mongodb-security-injection-attacks/
timelineRouter.route("/api/timeline")
    .get(async function (req, res) {
        try {
            var foo = req.foo.bar;
            const startDate = "01/01/2000";
            // ruleid:node_nosqli_js_injection
            const endDate = req.query.end;
            const query = { $where: "this.hidden == false" };

            if (startDate && endDate) {
                query["$where"] = "this.start >= new Date('" + startDate + "') && " +
                    "this.end <= new Date('" + endDate + "') &&" +
                    "this.hidden == false;";
            }

            const TimelineItem = await getTimelineItemModel();
            const timelineItems = await TimelineItem.find(query);
            console.log(colors.yellow(`# of Timeline Items retrieved: ${timelineItems.length}`));
            return res.json({ timelineItems: timelineItems });

        } catch (error) {
            res.status(500).send("There was an error retrieving timeline items.  Please try again later");
        }
    });

let username = req.query.username;
var query = { $where: `this.username == '${username}'` }
User.find(query, function (err, users) {
    if (err) {
        // Handle errors
    } else {
        res.render('userlookup', { title: 'User Lookup', users: users });
    }
});

app.post('/foo', function (req, res) {
    var query = {};
    query['$where'] = `this.email == '${req.body.email}'`;
    User.find(query, function (err, data) {
        if (err) {
            res.send(err);
        } else if (data) {
            res.send('User Login Successful');
        } else {
            res.send('Wrong Username Password Combination');
        }
    })
});
