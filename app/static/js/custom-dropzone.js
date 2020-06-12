$( document ).ready(function() {
    console.log("asdfasdf");
    Dropzone.options.myAwesomeDropzone = {
        maxFiles: 1,
        paramName: "file", // The name that will be used to transfer the file
        maxFilesize: 9999, // MB
        accept: function(file, done) {
            if (file.name == "justinbieber.jpg") {
                done("Naha, you don't.");
            }
            else { 
                done("OK");
                console.log("test");
            }
        }
    };
});