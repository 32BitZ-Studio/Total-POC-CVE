jQuery(function($){
    /* version: 1.0
     * Select/Upload image(s) event
     */
    $('body').on('click', '.misha_upload_image_button', function(e){
            e.preventDefault();

            var button = $(this),
            custom_uploader = wp.media({
                title: 'Insert file',

                library : {
                    //uploadedTo : wp.media.view.settings.post.id, 
                    type : 'image, audio, video, application/pdf'
                },
                button: {
                    text: 'Use this file' // button label text
                },
                multiple: false // for multiple image selection set to true
            }).on('select', function() { // it also has "open" and "close" events 
                var attachment = custom_uploader.state().get('selection').first().toJSON();

                $(button).removeClass('button, ').html('Upload').next().val(attachment.id).next().show();
                $(button).before('<a class="true_pre_image appended" target="_blank" href="' + attachment.url + '" style="max-width:95%;display:block;">View</a>');
          
            /* if you sen multiple to true, here is some code for getting the image IDs 
            
            var attachments = frame.state().get('selection'),
                attachment_ids = new Array(),
                i = 0;
            attachments.each(function(attachment) {
                attachment_ids[i] = attachment['id'];
                console.log( attachment );
                i++;
            });*/

        })
        .open();
    });

    /*
     * Remove image event
     */
    $('body').on('click', '.misha_remove_image_button', function(){
        $(this).prev().prev().val('');
        $(this).prev().addClass('').html('')
        $(this).hide();
        return false;
    });
});