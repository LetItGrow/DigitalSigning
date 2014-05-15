var keySizes = ['512', '1024', '2048'];
var testDocuments = [
    "Transferir 100€ a la cuenta 123-456-789",
    "Integer posuere erat a ante venenatis dapibus posuere velit aliquet.",
    "Vivamus sagittis lacus vel augue laoreet rutrum faucibus dolor auctor. Etiam porta sem malesuada magna mollis euismod. Maecenas faucibus mollis interdum. Morbi leo risus, porta ac consectetur ac, vestibulum at eros.\
\
    Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Maecenas sed diam eget risus varius blandit sit amet non magna. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus sagittis lacus vel augue laoreet rutrum faucibus dolor auctor. Vestibulum id ligula porta felis euismod semper.\
\
        Donec id elit non mi porta gravida at eget metus. Duis mollis, est non commodo luctus, nisi erat porttitor ligula, eget lacinia odio sem nec elit. Nullam id dolor id nibh ultricies vehicula ut id elit. Donec ullamcorper nulla non metus auctor fringilla. Sed posuere consectetur est at lobortis. Fusce dapibus, tellus ac cursus commodo, tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus.\
\
        Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Praesent commodo cursus magna, vel scelerisque nisl consectetur et. Vestibulum id ligula porta felis euismod semper. Morbi leo risus, porta ac consectetur ac, vestibulum at eros. Duis mollis, est non commodo luctus, nisi erat porttitor ligula, eget lacinia odio sem nec elit. Aenean lacinia bibendum nulla sed consectetur."
];

var ITERATIONS = 100;

function runEfficiencyTests(individualTestCallback, testDoneCallback, testErrorCallback) {
    var testDataList = [];
    // Create a function that will run recursively every time a test ends.
    var runNext = function () {
        // Check if all test are completed
        if(!testDataList.length>0) {
            // Al done
            testDoneCallback();
            return;
        }
        // Get the current test data
        var testData = testDataList.pop();
        // Send ajax request to obtain a generated key from the server
        $.ajax({
            "url": "api/genkeys",
            "type": "GET",
            "dataType": "json",
            "data": {
                "keySize": testData.keySize
            },
            "success": function (data) {
                console.log("Got private key: " + data.privateKey);
                // Runs the individual test for this key and document
                runSingleEfficiencyTest(data.privateKey, testData.keySize, testData.doc, individualTestCallback, testErrorCallback);
                // When ended, run next test
                runNext();
            },
            "error": function (jqXHR, textStatus, errorThrown) {
                testErrorCallback("Error generating keys: " + textStatus);
            }
        });
    };
    // Now, build the list of test data for each test to be executed
    // For each key size
    for (var sizeIndex = 0; sizeIndex < keySizes.length; sizeIndex++) {
        var keySize = keySizes[sizeIndex];
        // And each document
        for (var docIndex = 0; docIndex < testDocuments.length; docIndex++) {
            var doc = testDocuments[docIndex];
            testDataList.push({"keySize": keySize, "doc": doc});
        }
    }
    // Reverse the list (so pop() methods return the "first" item
    testDataList.reverse();
    // And start running tests
    runNext();

}

function runSingleEfficiencyTest(key, keySize, doc, individualTestCallback, testErrorCallback) {
    // Perform n iterations
    var lastSig = undefined;
    var totalElapsedTime = 0;
    for (var i = 0; i < ITERATIONS; i++) {
        var start = new Date().getTime();
        // Sign the document
        var sig = sign(key, doc);
        // Measure elapsed time
        totalElapsedTime += new Date().getTime() - start;
        // Check that matches the last one for this key and document
        if (lastSig && lastSig != sig) {
            testErrorCallback("Error: lastSig != sig");
            return;
        }
        lastSig = sig;
    }// Individual test done

    var meanTime = totalElapsedTime / ITERATIONS;
    individualTestCallback(meanTime, lastSig, key, keySize, doc);
}

function runValidationTests(allDoneCallback, errorCallback, verificationOkCallback, verificationNegativeCallback) {
    // Build the list of test data for each test to be executed
    var testDataList = getTestDataList();
    // Prepare a function that will run recursively every time a test ends.
    var runNext = function () {
        // Check if all test are completed
        if(!testDataList.length>0) {
            // Al done
            allDoneCallback();
            return;
        }
        // Extract the current test data from the list
        var testData = testDataList.pop();
        // Send ajax request to obtain a generated key from the server
        $.ajax({
            "url": "api/genkeys",
            "type": "GET",
            "dataType": "json",
            "data": {
                "keySize": testData.keySize
            },
            "success": function (data) {
                // Runs the individual test for this key and document
                runSingleValidationTest(data.publicKey, data.privateKey, testData.keySize, testData.doc, verificationOkCallback, verificationNegativeCallback);
                // When ended, run next test
                runNext();
            },
            "error": function (jqXHR, textStatus, errorThrown) {
                errorCallback("Error generating keys: " + textStatus);
            }
        });
    };

    // And start running tests
    runNext();

}

function runSingleValidationTest(publicKey, privateKey, keySize, doc, verificationOkCallback, verificationNegativeCallback) {
    // Perform n iterations
    var totalElapsedTime = 0;
    for (var i = 0; i < ITERATIONS; i++) {
        // Sign the document
        var sig = sign(privateKey, doc);
        // Do verification
        var start = new Date().getTime();
        var verifyed = verify(doc, sig, publicKey);
        // Measure elapsed time
        totalElapsedTime += new Date().getTime() - start;
        // End if failed
        if (!verifyed) {
            verificationNegativeCallback(publicKey, privateKey, keySize, doc);
            return;
        }
    }// Individual test done

    var meanTime = totalElapsedTime / ITERATIONS;
    verificationOkCallback(meanTime, publicKey, privateKey, keySize, doc);
}

function getTestDataList() {
    var testDataList = [];
    // For each key size
    for (var sizeIndex = 0; sizeIndex < keySizes.length; sizeIndex++) {
        var keySize = keySizes[sizeIndex];
        // And each document
        for (var docIndex = 0; docIndex < testDocuments.length; docIndex++) {
            var doc = testDocuments[docIndex];
            testDataList.push({"keySize": keySize, "doc": doc});
        }
    }
    // Reverse the list (so pop() methods return the "first" item
    testDataList.reverse();
    return testDataList;
}