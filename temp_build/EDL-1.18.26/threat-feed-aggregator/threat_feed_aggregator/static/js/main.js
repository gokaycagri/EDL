function confirmAction(event, message) {
    event.preventDefault();
    const element = event.currentTarget; 
    
    Swal.fire({
        title: 'Are you sure?',
        text: message,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ff0055',
        cancelButtonColor: '#444',
        confirmButtonText: 'Yes, do it!',
        background: '#1e1e1e',
        color: '#e0e0e0'
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
