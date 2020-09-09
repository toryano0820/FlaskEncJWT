
(function ($) {
    "use strict";


    /*==================================================================
    [ Validate ]*/
    var input = $('.validate-input .input100');

    $('.validate-form').on('submit', function(){
        var check = true;

        for(var i=0; i<input.length; i++) {
            resetValidate(input[i]);
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }

        return check;
    });


    $('.validate-form .input100').each(function(){
        $(this).focus(function(){
            hideValidate(this);
        });
    });

    function validate (input) {
        if($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
            if($(input).val().trim().match(/^[A-Za-z0-9]+([._][A-Za-z0-9]+)*@[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$/) == null) {
                return false;
            }
        }
        else {
            if($(input).val().trim() == ''){
                return false;
            }
        }
    }

    function showValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).addClass('alert-validate');
    }

    function hideValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).removeClass('alert-validate');

        resetValidate(input);
    }

    function resetValidate(input) {
        var thisAlert = $(input).parent();

        if($(input).attr('type') == 'email' || $(input).attr('name') == 'email')
            $(thisAlert).attr('data-validate', 'Valid email is required: ex@abc.xyz');
        else
            $(thisAlert).attr('data-validate', 'Password is required');
    }
})(jQuery);