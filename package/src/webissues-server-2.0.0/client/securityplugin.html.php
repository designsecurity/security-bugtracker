<?php if (!defined('WI_VERSION')) {
    die(-1);
} ?>


<div style="float: right">

<?php
$html = '<span aria-hidden="true" class="fa fa-pencil">Install Plugin</span>';
echo $this->link("/client/securityplugin.php?install=yes", $html);
$html = '<span aria-hidden="true" class="fa fa-remove">Uninstall Plugin</span>';
echo $this->link("/client/securityplugin.php?install=no", $html);

?>
</div>


<?php if ($install_security == "do") : ?>  
    <?php if ($error_install == 0) : ?>
  <div class="comment-text">Installation completed</div>
    <?php else : ?>
  <div class="comment-text">Error: <?php echo $error_install; ?></div>
    <?php endif ?>
<?php elseif ($install_security == "no") : ?>
<div class="comment-text">Uninstallation completed</div>
<?php elseif ($install_security == "yes") : ?>
<div class="comment-text">Installation</div>

    <?php
    $form->renderFormOpen();
    $form->renderText($this->t('openvas_ws_login:'), 'openvas_ws_login', array( 'size' => 80 ));
    $form->renderText($this->t('openvas_ws_password:'), 'openvas_ws_password', array( 'size' => 80 ));
    $endpoint = "http://localhost/webissues-server-2.0.0/client/security_tools/openvas/openvas.php";
    $array = array( 'size' => 80, "value" => $endpoint );
    $form->renderText($this->t('openvas_ws_endpoint:'), 'openvas_ws_endpoint', $array);
    $form->renderText($this->t('type_folder_bugs:'), 'type_folder_bugs', array( 'size' => 80, "value" => "2" ));
    ?>
<div class="form-submit">
    <?php $form->renderSubmit($this->t('OK'), 'ok'); ?>
    <?php $form->renderSubmit($this->t('Cancel'), 'cancel'); ?>
</div>
    <?php $form->renderFormClose() ?>

<?php elseif (empty($install_security) && !empty($alertscanid)) : ?>
<div class="comment-text">Scan openvas finished</div>
<?php else : ?>
<div class="comment-text">Choose an option</div>
<?php endif ?>
