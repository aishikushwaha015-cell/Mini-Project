/* ==================================================================== */
/* DRISHTI AI — Scan history & reports                                  */
/* Confirmation dialog and print action only. No charts, no polling.    */
/* ==================================================================== */

(function () {
  'use strict';

  var dialog = document.getElementById('confirm-dialog');
  var dialogTitle = document.getElementById('confirm-title');
  var dialogMessage = document.getElementById('confirm-message');
  var confirmButton = document.getElementById('confirm-accept');
  var cancelButton = document.getElementById('confirm-cancel');
  var pendingForm = null;

  function fallbackConfirm(form) {
    var message =
      form.getAttribute('data-confirm-message') ||
      'Please confirm this action.';
    if (window.confirm(message)) {
      form.dataset.confirmed = '1';
      form.requestSubmit();
    }
  }

  if (dialog && dialogTitle && dialogMessage && confirmButton && cancelButton) {
    document.addEventListener('submit', function (event) {
      var form = event.target;
      if (!form || typeof form.matches !== 'function') {
        return;
      }
      if (!form.matches('form[data-confirm]')) {
        return;
      }
      if (form.dataset.confirmed === '1') {
        return;
      }

      if (typeof dialog.showModal !== 'function') {
        fallbackConfirm(form);
        event.preventDefault();
        return;
      }

      event.preventDefault();
      pendingForm = form;
      dialogTitle.textContent =
        form.getAttribute('data-confirm-title') || 'Please confirm';
      dialogMessage.textContent =
        form.getAttribute('data-confirm-message') ||
        'Please confirm this action.';
      confirmButton.textContent =
        form.getAttribute('data-confirm-label') || 'Confirm';
      dialog.showModal();
    });

    confirmButton.addEventListener('click', function () {
      if (!pendingForm) {
        return;
      }
      var form = pendingForm;
      pendingForm = null;
      form.dataset.confirmed = '1';
      dialog.close();
      form.requestSubmit();
    });

    cancelButton.addEventListener('click', function () {
      pendingForm = null;
      dialog.close();
    });

    dialog.addEventListener('click', function (event) {
      if (event.target === dialog) {
        pendingForm = null;
        dialog.close();
      }
    });

    dialog.addEventListener('close', function () {
      pendingForm = null;
    });
  }

  var printButtons = document.querySelectorAll('[data-print]');
  for (var i = 0; i < printButtons.length; i += 1) {
    printButtons[i].addEventListener('click', function () {
      window.print();
    });
  }
})();
