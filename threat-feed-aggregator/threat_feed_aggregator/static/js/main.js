function confirmAction(event, message) {
    event.preventDefault();
    const element = event.currentTarget; 
    
    Swal.fire({
        title: 'Are you sure?',
        text: message,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ff2d55',
        cancelButtonColor: '#243044',
        confirmButtonText: 'Yes, do it!',
        background: '#1a2233',
        color: '#e2e8f0'
    }).then((result) => {
        if (result.isConfirmed) {
            if (element.tagName === 'A') {
                window.location.href = element.href;
            } else if (element.tagName === 'BUTTON' || element.tagName === 'INPUT') {
                const form = element.closest('form');
                if (form) form.submit();
            }
        }
    });
    return false;
}
